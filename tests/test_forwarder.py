from email import message_from_bytes

import pytest

from forwarder.handler import FORWARDED_HEADER, Config, forward, rewrite, skip_reason

CONFIG = Config(
    bucket="inbound-bucket",
    prefix="inbound/",
    forward_from="hello@app.example.com",
    forward_to="owner@example.org",
)

RAW = (
    b"Return-Path: <bounce@sender.example.net>\r\n"
    b"DKIM-Signature: v=1; a=rsa-sha256; d=sender.example.net; b=abc\r\n"
    b"From: Jane Sender <jane@sender.example.net>\r\n"
    b"Sender: list@sender.example.net\r\n"
    b"To: hello@app.example.com\r\n"
    b"Subject: Hi there\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Body text\r\n"
)


def _receipt(spam="PASS", virus="PASS", dmarc="PASS", dmarc_policy="NONE"):
    receipt = {
        "spamVerdict": {"status": spam},
        "virusVerdict": {"status": virus},
        "dmarcVerdict": {"status": dmarc},
    }
    if dmarc_policy is not None:
        receipt["dmarcPolicy"] = dmarc_policy
    return receipt


def _event(message_id="msg-1", **receipt_kwargs):
    return {
        "Records": [
            {"ses": {"mail": {"messageId": message_id}, "receipt": _receipt(**receipt_kwargs)}}
        ]
    }


class FakeS3:
    def __init__(self, body):
        self._body = body
        self.gets = []

    def get_object(self, Bucket, Key):
        self.gets.append((Bucket, Key))
        return {"Body": FakeBody(self._body)}


class FakeBody:
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data


class FakeSes:
    def __init__(self):
        self.calls = []

    def send_email(self, **kwargs):
        self.calls.append(kwargs)
        return {"MessageId": "out-1"}


# --- skip_reason ---


def test_clean_mail_is_forwarded():
    assert skip_reason(_receipt()) is None


@pytest.mark.parametrize(
    "kwargs, reason",
    [
        ({"virus": "FAIL"}, "virus"),
        ({"spam": "FAIL"}, "spam"),
        ({"dmarc": "FAIL", "dmarc_policy": "REJECT"}, "dmarc"),
    ],
)
def test_failed_verdicts_are_skipped(kwargs, reason):
    assert skip_reason(_receipt(**kwargs)) == reason


@pytest.mark.parametrize(
    "kwargs",
    [
        {"spam": "GRAY"},
        {"spam": "PROCESSING_FAILED", "virus": "PROCESSING_FAILED"},
        {"dmarc": "FAIL", "dmarc_policy": "NONE"},
        {"dmarc": "FAIL", "dmarc_policy": None},
    ],
)
def test_inconclusive_or_lenient_verdicts_still_forward(kwargs):
    assert skip_reason(_receipt(**kwargs)) is None


# --- rewrite ---


def test_rewrite_sets_verified_from_with_original_name():
    msg = message_from_bytes(rewrite(RAW, CONFIG.forward_from))
    assert msg["From"] == "Jane Sender via Sarcastifyer <hello@app.example.com>"


def test_rewrite_points_reply_to_at_original_sender():
    msg = message_from_bytes(rewrite(RAW, CONFIG.forward_from))
    assert msg["Reply-To"] == "Jane Sender <jane@sender.example.net>"


def test_rewrite_keeps_existing_reply_to():
    raw = RAW.replace(b"Subject:", b"Reply-To: replies@sender.example.net\r\nSubject:")
    msg = message_from_bytes(rewrite(raw, CONFIG.forward_from))
    assert msg.get_all("Reply-To") == ["replies@sender.example.net"]


def test_rewrite_drops_headers_ses_would_reject_or_that_no_longer_verify():
    msg = message_from_bytes(rewrite(RAW, CONFIG.forward_from))
    for header in ("Return-Path", "Sender", "DKIM-Signature"):
        assert header not in msg
    assert msg.get_all("From") == ["Jane Sender via Sarcastifyer <hello@app.example.com>"]


def test_rewrite_keeps_subject_body_and_marks_forwarded():
    msg = message_from_bytes(rewrite(RAW, CONFIG.forward_from))
    assert msg["Subject"] == "Hi there"
    assert msg.get_payload().strip() == "Body text"
    assert msg[FORWARDED_HEADER] == "1"


def test_rewrite_decodes_encoded_display_name():
    raw = RAW.replace(b"Jane Sender", b"=?utf-8?b?SsO2cmc=?=")  # "Jörg"
    msg = message_from_bytes(rewrite(raw, CONFIG.forward_from))
    from email.header import decode_header, make_header

    assert str(make_header(decode_header(msg["From"]))) == (
        "Jörg via Sarcastifyer <hello@app.example.com>"
    )


def test_rewrite_strips_line_breaks_from_display_name():
    # An encoded word that decodes to CRLF + a header must not become a real header.
    raw = RAW.replace(b"From: Jane Sender", b"From: =?utf-8?q?Jane=0D=0ABcc:_x@evil.example?=")
    out = rewrite(raw, CONFIG.forward_from)
    msg = message_from_bytes(out)
    assert "Bcc" not in msg
    assert "\n" not in msg["From"] and "\r" not in msg["From"]


def test_rewrite_handles_missing_from():
    raw = RAW.replace(b"From: Jane Sender <jane@sender.example.net>\r\n", b"")
    msg = message_from_bytes(rewrite(raw, CONFIG.forward_from))
    assert msg["From"] == "Unknown sender via Sarcastifyer <hello@app.example.com>"
    assert "Reply-To" not in msg


# --- forward ---


def test_forward_reads_message_from_s3_and_sends_to_owner():
    s3, ses = FakeS3(RAW), FakeSes()
    assert forward(_event("msg-42"), s3, ses, CONFIG) == "forwarded"
    assert s3.gets == [("inbound-bucket", "inbound/msg-42")]
    (call,) = ses.calls
    assert call["FromEmailAddress"] == "hello@app.example.com"
    assert call["Destination"] == {"ToAddresses": ["owner@example.org"]}
    sent = message_from_bytes(call["Content"]["Raw"]["Data"])
    assert sent["Reply-To"] == "Jane Sender <jane@sender.example.net>"


def test_forward_skips_flagged_mail_without_reading_it():
    s3, ses = FakeS3(RAW), FakeSes()
    assert forward(_event(virus="FAIL"), s3, ses, CONFIG) == "skipped: virus"
    assert s3.gets == [] and ses.calls == []


def test_forward_skips_mail_it_already_forwarded():
    raw = RAW.replace(b"Subject:", FORWARDED_HEADER.encode() + b": 1\r\nSubject:")
    s3, ses = FakeS3(raw), FakeSes()
    assert forward(_event(), s3, ses, CONFIG) == "skipped: loop"
    assert ses.calls == []
