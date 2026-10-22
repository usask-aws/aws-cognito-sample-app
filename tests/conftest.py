import pytest

from app import create_app, session_auth
from app.audit import AuditLog
from app.directory import ACTIVE
from app.guardrails import DailyTokenBrake, RateLimiter
from app.oidc import OidcClient
from tests.oidc_fakes import ADMIN_SUB, USER_SUB, FakeHttp, make_pools


class FakeTransformer:
    """Yields a fixed sarcastic string; returns a fixed token count."""

    def __init__(self, chunks=("Oh, ", "brilliant."), tokens=5):
        self._chunks = chunks
        self._tokens = tokens

    def stream_transform(self, text):
        for c in self._chunks:
            yield c
        return self._tokens


class FakeMailer:
    """Records sends instead of calling SES; optionally fails every send."""

    def __init__(self, fail=False):
        self.sent = []
        self._fail = fail

    def send(self, to, subject, body):
        if self._fail:
            raise RuntimeError("ses down")
        self.sent.append({"to": to, "subject": subject, "body": body})


class FakeDirectory:
    """Answers session revalidation. Set statuses[(pool, sub)], emails[(pool, sub)]
    or error per test. The default email is the one sign_in() uses for that pool."""

    def __init__(self):
        self.statuses = {}
        self.emails = {}
        self.error = None
        self.status_calls = []

    def account_status(self, pool, sub):
        self.status_calls.append((pool, sub))
        if self.error:
            raise self.error
        default_email = "admin@example.com" if pool == "admin" else "pat@example.com"
        return self.statuses.get((pool, sub), ACTIVE), self.emails.get((pool, sub), default_email)


class FakeClock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _secret_provider(name):
    from app import config

    return {
        config.SECRET_FLASK_SIGNING_KEY: "test-signing-key",
        config.SECRET_ANTHROPIC_API_KEY: "test-api-key",
        config.SECRET_COGNITO_USERS_CLIENT: "users-client-secret",
        config.SECRET_COGNITO_ADMINS_CLIENT: "admins-client-secret",
    }[name]


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def make_app(clock):
    def _make(
        transformer=None,
        rate_limiter=None,
        token_brake=None,
        mailer=None,
        directory=None,
        account_client=None,
        http=None,
        audit_lines=None,
    ):
        app = create_app(
            secret_provider=_secret_provider,
            transformer=transformer or FakeTransformer(),
            mailer=mailer or FakeMailer(),
            rate_limiter=rate_limiter or RateLimiter(2, 60),
            token_brake=token_brake or DailyTokenBrake(50_000),
            pools=make_pools(),
            oidc_client=OidcClient(http or FakeHttp(), clock=clock),
            directory=directory or FakeDirectory(),
            account_client=account_client or object(),
            # Audit lines go to audit_lines (a list) when given, else nowhere.
            audit_log=AuditLog(
                write=audit_lines.append if audit_lines is not None else lambda line: None,
                clock=clock,
            ),
            clock=clock,
        )
        app.config.update(TESTING=True)
        return app

    return _make


@pytest.fixture
def client(make_app):
    return make_app().test_client()


def sign_in(
    client,
    pool="user",
    sub=None,
    email=None,
    given_name="Pat",
    family_name="Example",
    access_token="aaa.bbb.ccc",
    access_exp=None,
):
    """Put a signed-in session in the test client's cookie, skipping managed login."""
    now = client.application.extensions["clock"]()
    claims = {
        "sub": sub or (ADMIN_SUB if pool == "admin" else USER_SUB),
        "email": email or ("admin@example.com" if pool == "admin" else "pat@example.com"),
        "given_name": given_name,
        "family_name": family_name,
    }
    with client.session_transaction() as sess:
        session_auth.establish(
            sess,
            pool,
            claims,
            now,
            access_token if pool == "admin" else None,
            access_exp if access_exp is not None else int(now) + 3600,
        )
    return client


def csrf(client):
    with client.session_transaction() as sess:
        return session_auth.csrf_token(sess)
