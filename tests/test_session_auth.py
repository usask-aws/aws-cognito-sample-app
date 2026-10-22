import logging

import pytest
from flask.sessions import SecureCookieSession

from app import session_auth as sa
from app.directory import ACTIVE, DISABLED, MISSING, Throttled

NOW = 1_800_000_000
LIFETIME = 28_800
CLAIMS = {
    "sub": "11111111-1111-4111-8111-111111111111",
    "email": "pat@example.com",
    "given_name": "Pat",
    "family_name": "Example",
}


def _signed_in(pool="user", now=NOW, **kwargs):
    sess = SecureCookieSession()
    sa.establish(sess, pool, CLAIMS, now, **kwargs)
    return sess


class StatusDirectory:
    def __init__(self, status=ACTIVE, error=None, email=CLAIMS["email"]):
        self.status, self.error, self.email, self.calls = status, error, email, []

    def account_status(self, pool, sub):
        self.calls.append((pool, sub))
        if self.error:
            raise self.error
        return self.status, self.email


def test_establish_user_session():
    sess = _signed_in()
    assert sess.permanent is True
    assert {k: sess[k] for k in ("sub", "pool", "email", "auth_time", "checked_at")} == {
        "sub": CLAIMS["sub"],
        "pool": "user",
        "email": "pat@example.com",
        "auth_time": NOW,
        "checked_at": NOW,
    }
    assert "access_token" not in sess and "access_exp" not in sess
    assert isinstance(sess["csrf"], str) and len(sess["csrf"]) >= 32


def test_user_session_never_stores_access_token():
    sess = _signed_in("user", access_token="tok", access_exp=NOW + 3600)
    assert "access_token" not in sess


def test_establish_admin_session_keeps_access_token():
    sess = _signed_in("admin", access_token="tok", access_exp=NOW + 3600)
    assert sess["access_token"] == "tok" and sess["access_exp"] == NOW + 3600


def test_establish_clears_previous_session():
    sess = SecureCookieSession({"stale": 1, "login": {"state": "x"}})
    sa.establish(sess, "user", CLAIMS, NOW)
    assert "stale" not in sess and "login" not in sess


def test_establish_rejects_unknown_pool():
    with pytest.raises(ValueError):
        sa.establish(SecureCookieSession(), "other", CLAIMS, NOW)


def test_load_identity():
    ident = sa.load_identity(_signed_in(), NOW + 10, LIFETIME)
    assert ident == sa.Identity(CLAIMS["sub"], "user", "pat@example.com", "Pat", "Example")
    assert ident.display_name == "Pat Example" and not ident.is_admin
    assert sa.load_identity(_signed_in("admin"), NOW, LIFETIME).is_admin


def test_session_expires_after_lifetime():
    sess = _signed_in()
    assert sa.load_identity(sess, NOW + LIFETIME - 1, LIFETIME) is not None
    assert sa.load_identity(sess, NOW + LIFETIME, LIFETIME) is None
    assert dict(sess) == {}


def test_signed_out_session_keeps_pending_login():
    sess = SecureCookieSession()
    sa.begin_login(sess, sa.PendingLogin("user", "s", "n", "v", "/"))
    assert sa.load_identity(sess, NOW, LIFETIME) is None
    assert sa.pop_pending(sess).state == "s"


def test_pending_login_is_single_use():
    sess = SecureCookieSession()
    pending = sa.PendingLogin("admin", "s", "n", "v", "/account")
    sa.begin_login(sess, pending)
    assert sa.pop_pending(sess) == pending
    assert sa.pop_pending(sess) is None


def test_pop_pending_ignores_malformed():
    assert sa.pop_pending(SecureCookieSession({"login": {"state": "s"}})) is None
    assert sa.pop_pending(SecureCookieSession({"login": "junk"})) is None


def test_needs_revalidation_after_interval():
    sess = _signed_in()
    assert not sa.needs_revalidation(sess, NOW + 899, 900)
    assert sa.needs_revalidation(sess, NOW + 900, 900)


@pytest.mark.parametrize("pool", ["user", "admin"])
def test_revalidate_active_updates_checked_at(pool):
    sess = _signed_in(pool)
    ident = sa.load_identity(sess, NOW, LIFETIME)
    directory = StatusDirectory(ACTIVE)
    assert sa.revalidate(sess, ident, NOW + 900, directory, logging.getLogger()) == ident
    assert sess["checked_at"] == NOW + 900
    assert directory.calls == [(pool, CLAIMS["sub"])]


@pytest.mark.parametrize("pool", ["user", "admin"])
@pytest.mark.parametrize("status", [DISABLED, MISSING])
def test_revalidate_disabled_or_missing_signs_out(pool, status):
    sess = _signed_in(pool)
    ident = sa.load_identity(sess, NOW, LIFETIME)
    assert sa.revalidate(sess, ident, NOW + 900, StatusDirectory(status), logging.getLogger()) is None
    assert dict(sess) == {}


def test_revalidate_changed_email_signs_out():
    # An admin's Change email ends sessions opened with the old address.
    sess = _signed_in()
    ident = sa.load_identity(sess, NOW, LIFETIME)
    directory = StatusDirectory(ACTIVE, email="new@example.com")
    assert sa.revalidate(sess, ident, NOW + 900, directory, logging.getLogger()) is None
    assert dict(sess) == {}


def test_revalidate_throttled_keeps_session_and_retries():
    sess = _signed_in()
    ident = sa.load_identity(sess, NOW, LIFETIME)
    directory = StatusDirectory(error=Throttled("TooManyRequestsException"))
    assert sa.revalidate(sess, ident, NOW + 900, directory, logging.getLogger()) == ident
    assert sess["checked_at"] == NOW  # unchanged, so the next request checks again
    assert sa.needs_revalidation(sess, NOW + 901, 900)


def test_admin_access_token():
    sess = _signed_in("admin", access_token="tok", access_exp=NOW + 3600)
    assert sa.admin_access_token(sess, NOW) == "tok"
    assert sa.admin_access_token(sess, NOW + 3540) is None  # within the 60 s margin
    assert sa.admin_access_token(_signed_in("admin"), NOW) is None
    assert sa.admin_access_token(_signed_in("user"), NOW) is None


def test_csrf_token_and_check():
    sess = SecureCookieSession()
    token = sa.csrf_token(sess)
    assert sa.csrf_token(sess) == token
    assert sa.csrf_ok(sess, token)
    assert not sa.csrf_ok(sess, token + "x")
    assert not sa.csrf_ok(sess, None)
    assert not sa.csrf_ok(SecureCookieSession(), token)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("/account", "/account"),
        ("/admin?page=2", "/admin?page=2"),
        ("//evil.example", "/d"),
        ("/\\evil.example", "/d"),
        ("https://evil.example/", "/d"),
        ("account", "/d"),
        ("/a b", "/d"),
        ("/a\nb", "/d"),
        ("", "/d"),
        (None, "/d"),
        (["/x"], "/d"),
    ],
)
def test_safe_next(value, expected):
    assert sa.safe_next(value, "/d") == expected
