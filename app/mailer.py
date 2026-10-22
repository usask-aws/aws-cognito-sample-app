from email.utils import formataddr


def build_body(text: str, result: str) -> str:
    return f"Normal text:\n {text}\nResult:\n  {result}\n"


class SesMailer:
    """Sends plain-text email through the SES v2 API."""

    def __init__(self, client, sender: str, sender_name: str = ""):
        self._client = client
        self._sender = formataddr((sender_name, sender)) if sender_name else sender

    def send(self, to: str, subject: str, body: str) -> None:
        self._client.send_email(
            FromEmailAddress=self._sender,
            Destination={"ToAddresses": [to]},
            Content={
                "Simple": {
                    "Subject": {"Data": subject, "Charset": "UTF-8"},
                    "Body": {"Text": {"Data": body, "Charset": "UTF-8"}},
                }
            },
        )
