import pytest

from tests.conftest import sign_in


def test_healthz_ok(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


@pytest.mark.parametrize("path", ["/", "/healthz", "/static/styles.css", "/no-such-page"])
def test_security_headers_on_every_response(client, path):
    resp = client.get(path)
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Content-Security-Policy"] == "frame-ancestors 'none'"


def test_index_signed_out_shows_landing(client):
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert 'href="/auth/login"' in html
    assert "0/5000 characters" not in html


def test_signed_in_index(client):
    sign_in(client)
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"0/5000 characters" in resp.data
    assert b"Limited/Restricted" in resp.data


def test_transform_requires_auth(client):
    resp = client.post("/transform", json={"text": "hi"})
    assert resp.status_code == 401


def test_transform_streams_result(client):
    sign_in(client)
    resp = client.post("/transform", json={"text": "please help me"})
    assert resp.status_code == 200
    assert resp.mimetype == "text/event-stream"
    body = resp.get_data(as_text=True)
    assert "Oh, " in body
    assert "brilliant." in body


def test_transform_rejects_oversized_input(client):
    sign_in(client)
    resp = client.post("/transform", json={"text": "x" * 5001})
    assert resp.status_code == 413


def test_transform_rate_limited(make_app):
    from app.guardrails import RateLimiter

    app = make_app(rate_limiter=RateLimiter(2, 60))
    c = app.test_client()
    sign_in(c)
    assert c.post("/transform", json={"text": "a"}).status_code == 200
    assert c.post("/transform", json={"text": "a"}).status_code == 200
    assert c.post("/transform", json={"text": "a"}).status_code == 429


def test_transform_daily_brake(make_app):
    from app.guardrails import DailyTokenBrake

    brake = DailyTokenBrake(cap=1)
    brake.record(1)  # pre-trip
    app = make_app(token_brake=brake)
    c = app.test_client()
    sign_in(c)
    resp = c.post("/transform", json={"text": "a"})
    assert resp.status_code == 429


class RaisingTransformer:
    def stream_transform(self, text):
        yield "partial"
        raise RuntimeError("boom")


def test_transform_stream_error_emits_error_event(make_app):
    app = make_app(transformer=RaisingTransformer())
    c = app.test_client()
    sign_in(c)
    resp = c.post("/transform", json={"text": "a"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "event: error" in body


def test_transform_rejects_non_string_input(client):
    sign_in(client)
    resp = client.post("/transform", json={"text": 123})
    assert resp.status_code == 400


def test_index_has_counter_and_notice_and_script(client):
    sign_in(client)
    html = client.get("/").get_data(as_text=True)
    assert 'id="counter"' in html
    assert "0/5000 characters" in html
    assert "Don't paste Limited/Restricted data" in html
    assert "app.js" in html


def _provider_missing_api_key(name):
    from app import config
    from app.secrets import SecretNotFoundError

    if name == config.SECRET_ANTHROPIC_API_KEY:
        raise SecretNotFoundError(name)
    return {
        config.SECRET_FLASK_SIGNING_KEY: "test-signing-key",
        config.SECRET_COGNITO_USERS_CLIENT: "users-client-secret",
        config.SECRET_COGNITO_ADMINS_CLIENT: "admins-client-secret",
    }[name]


def test_app_starts_without_anthropic_key():
    # Production path (transformer=None) must still boot when the Anthropic
    # key secret is absent; other secrets remain required.
    from app import create_app

    app = create_app(secret_provider=_provider_missing_api_key)
    assert app.test_client().get("/healthz").status_code == 200


def test_transform_returns_missing_key_message_when_key_absent():
    from app import config, create_app

    app = create_app(secret_provider=_provider_missing_api_key)
    app.config.update(TESTING=True)
    c = app.test_client()
    sign_in(c)
    resp = c.post("/transform", json={"text": "please help me"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "event: error" not in body
    assert config.MISSING_API_KEY_MESSAGE in body


def _streamed_text(resp):
    """Concatenate the JSON-encoded `data:` chunks of an SSE transform reply."""
    import json

    events = resp.get_data(as_text=True).split("\n\n")
    return "".join(
        json.loads(e[len("data: "):])
        for e in events
        if e.startswith("data: ") and e != "data: end"
    )


def test_transform_emails_signed_in_user_when_asked(make_app):
    from tests.conftest import FakeMailer

    mailer = FakeMailer()
    c = sign_in(make_app(mailer=mailer).test_client())
    resp = c.post("/transform", json={"text": "hi", "email": True})
    assert _streamed_text(resp) == "Oh, brilliant.\nEmail was sent to pat@example.com"
    assert mailer.sent == [
        {
            "to": "pat@example.com",
            "subject": "Sarcastifyer output",
            "body": "Normal text:\n hi\nResult:\n  Oh, brilliant.\n",
        }
    ]


def test_transform_ignores_any_address_from_the_client(make_app):
    from tests.conftest import FakeMailer

    mailer = FakeMailer()
    c = sign_in(make_app(mailer=mailer).test_client())
    c.post(
        "/transform",
        json={"text": "hi", "email": True, "email-recipient": "x", "to": "evil@example.net"},
    ).get_data()
    assert [m["to"] for m in mailer.sent] == ["pat@example.com"]


@pytest.mark.parametrize("payload", [{}, {"email": False}])
def test_transform_does_not_email_unless_asked(make_app, payload):
    from tests.conftest import FakeMailer

    mailer = FakeMailer()
    c = sign_in(make_app(mailer=mailer).test_client())
    resp = c.post("/transform", json={"text": "hi", **payload})
    assert _streamed_text(resp) == "Oh, brilliant."
    assert mailer.sent == []


@pytest.mark.parametrize("value", ["yes", 1, None, ["x"], "pat@example.com"])
def test_transform_rejects_non_boolean_email_flag(client, value):
    sign_in(client)
    resp = client.post("/transform", json={"text": "hi", "email": value})
    assert resp.status_code == 400
    assert resp.get_json() == {"error": "Invalid input."}


def test_transform_reports_failed_email_without_error_event(make_app):
    from tests.conftest import FakeMailer

    c = sign_in(make_app(mailer=FakeMailer(fail=True)).test_client())
    resp = c.post("/transform", json={"text": "hi", "email": True})
    assert resp.status_code == 200
    assert "event: error" not in resp.get_data(as_text=True)
    assert _streamed_text(resp) == "Oh, brilliant.\nEmail could not be sent to pat@example.com"


def test_transform_does_not_email_when_stream_fails(make_app):
    from tests.conftest import FakeMailer

    mailer = FakeMailer()
    c = sign_in(make_app(transformer=RaisingTransformer(), mailer=mailer).test_client())
    body = c.post("/transform", json={"text": "a", "email": True}).get_data(as_text=True)
    assert "Email was sent" not in body
    assert mailer.sent == []


def test_rate_limit_is_per_user_across_sessions(make_app):
    from app.guardrails import RateLimiter

    app = make_app(rate_limiter=RateLimiter(2, 60))
    first, second = app.test_client(), app.test_client()
    sign_in(first)
    sign_in(second)  # same sub, a fresh session
    assert first.post("/transform", json={"text": "a"}).status_code == 200
    assert first.post("/transform", json={"text": "a"}).status_code == 200
    assert second.post("/transform", json={"text": "a"}).status_code == 429
    other = sign_in(app.test_client(), sub="33333333-3333-4333-8333-333333333333")
    assert other.post("/transform", json={"text": "a"}).status_code == 200


def test_index_has_email_me_checkbox(client):
    sign_in(client)
    html = client.get("/").get_data(as_text=True)
    assert '<input type="checkbox" id="email-me">' in html
    assert '<label for="email-me">Email me the result</label>' in html
    assert "email-recipient" not in html
