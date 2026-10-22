from app.mailer import SesMailer, build_body


class FakeSesClient:
    def __init__(self):
        self.calls = []

    def send_email(self, **kwargs):
        self.calls.append(kwargs)
        return {"MessageId": "abc"}


def test_build_body_layout():
    assert build_body("plain", "sarcastic") == (
        "Normal text:\n plain\nResult:\n  sarcastic\n"
    )


def test_ses_mailer_sends_plain_text_from_configured_sender():
    client = FakeSesClient()
    SesMailer(client, "sender@example.com").send("to@example.com", "Subj", "Body")
    assert client.calls == [
        {
            "FromEmailAddress": "sender@example.com",
            "Destination": {"ToAddresses": ["to@example.com"]},
            "Content": {
                "Simple": {
                    "Subject": {"Data": "Subj", "Charset": "UTF-8"},
                    "Body": {"Text": {"Data": "Body", "Charset": "UTF-8"}},
                }
            },
        }
    ]


def test_ses_mailer_adds_display_name_when_given():
    client = FakeSesClient()
    SesMailer(client, "sender@example.com", "Example App").send("to@example.com", "S", "B")
    assert client.calls[0]["FromEmailAddress"] == "Example App <sender@example.com>"
