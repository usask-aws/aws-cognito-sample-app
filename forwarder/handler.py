"""SES inbound forwarder (Lambda).

An SES receipt rule stores each accepted message in S3, then invokes this function.
It re-sends the message to one owner address. From becomes "<original name> via Sarcastifyer <forward_from>" and
Reply-To points at the original sender. Logs carry message IDs and verdicts only,
never content.
"""

import logging
import os
from dataclasses import dataclass
from email import message_from_bytes
from email.header import decode_header, make_header
from email.utils import formataddr, parseaddr

log = logging.getLogger()
log.setLevel(logging.INFO)

FORWARDED_HEADER = "X-Sarcastifyer-Forwarded"
# Headers removed before re-sending.
DROP_HEADERS = ("From", "Sender", "Return-Path", "DKIM-Signature")
MAX_NAME_LEN = 100


@dataclass(frozen=True)
class Config:
    bucket: str
    prefix: str
    forward_from: str
    forward_to: str

    @classmethod
    def from_env(cls):
        return cls(
            bucket=os.environ["INBOUND_BUCKET"],
            prefix=os.environ["INBOUND_PREFIX"],
            forward_from=os.environ["FORWARD_FROM"],
            forward_to=os.environ["FORWARD_TO"],
        )


def skip_reason(receipt):
    """Why not to forward, or None. Only definite failures are dropped."""
    if receipt.get("virusVerdict", {}).get("status") == "FAIL":
        return "virus"
    if receipt.get("spamVerdict", {}).get("status") == "FAIL":
        return "spam"
    if (
        receipt.get("dmarcVerdict", {}).get("status") == "FAIL"
        and receipt.get("dmarcPolicy") == "REJECT"
    ):
        return "dmarc"
    return None


def _display_name(raw_from):
    name, addr = parseaddr(str(make_header(decode_header(raw_from))))
    name = " ".join((name or addr).split())  # collapses CR/LF and runs of whitespace
    return name[:MAX_NAME_LEN] or "Unknown sender"


def rewrite(raw, forward_from):
    """Return the message re-addressed From forward_from."""
    msg = message_from_bytes(raw)
    original_from = msg["From"]
    for header in DROP_HEADERS:
        del msg[header]

    name = _display_name(original_from) if original_from else "Unknown sender"
    msg["From"] = formataddr((f"{name} via Sarcastifyer", forward_from), charset="utf-8")
    if original_from and "Reply-To" not in msg:
        msg["Reply-To"] = str(original_from)
    msg[FORWARDED_HEADER] = "1"
    return msg.as_bytes()


def forward(event, s3, ses, config):
    record = event["Records"][0]["ses"]
    message_id = record["mail"]["messageId"]

    reason = skip_reason(record["receipt"])
    if reason:
        log.info("skip %s: %s", message_id, reason)
        return f"skipped: {reason}"

    raw = s3.get_object(Bucket=config.bucket, Key=config.prefix + message_id)["Body"].read()
    if FORWARDED_HEADER in message_from_bytes(raw):
        log.info("skip %s: loop", message_id)
        return "skipped: loop"

    ses.send_email(
        FromEmailAddress=config.forward_from,
        Destination={"ToAddresses": [config.forward_to]},
        Content={"Raw": {"Data": rewrite(raw, config.forward_from)}},
    )
    log.info("forwarded %s", message_id)
    return "forwarded"


def handler(event, context):
    import boto3

    return forward(event, boto3.client("s3"), boto3.client("sesv2"), Config.from_env())
