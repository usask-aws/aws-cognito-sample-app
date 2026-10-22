import secrets
import urllib.parse

import pytest

from app.directory import DISABLED, MISSING, Throttled
from tests.conftest import FakeDirectory, csrf, sign_in
from tests.oidc_fakes import (
    ADMIN_SUB,
    USER_SUB,
    FakeHttp,
    SigningKey,
    access_claims,
    id_claims,
    make_pools,
)

POOLS = make_pools()


@pytest.fixture(scope="module")
def key():
    return SigningKey("kid-1")


@pytest.fixture
def http(key):
    fake = FakeHttp()
    fake.publish(POOLS["user"], key)
    fake.publish(POOLS["admin"], key)
    return fake


@pytest.fixture
def directory():
    return FakeDirectory()


@pytest.fixture
def client(make_app, http, directory):
    return make_app(http=http, directory=directory).test_client()


def _query(url):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))


def _start(client, path="/auth/login"):
    """Begin sign-in; return the state and nonce sent to managed login."""
    resp = client.get(path)
    assert resp.status_code == 302
    q = _query(resp.headers["Location"])
    return q["state"], q["nonce"]


def _issue_tokens(http, key, pool_name, nonce, now, claims_pool=None, **id_overrides):
    """Make the fake token endpoint for pool_name return tokens for claims_pool."""
    claims_pool = POOLS[claims_pool or pool_name]
    http.token_responses[POOLS[pool_name].token_endpoint] = {
        "id_token": key.sign(id_claims(claims_pool, nonce, now, **id_overrides)),
        "access_token": key.sign(access_claims(claims_pool, now)),
        "refresh_token": "never-stored",
        "token_type": "Bearer",
        "expires_in": 3600,
    }


def _signed_out(client):
    with client.session_transaction() as sess:
        return "sub" not in sess and "login" not in sess


def test_login_redirects_to_user_pool_managed_login(client):
    resp = client.get("/auth/login")
    location = resp.headers["Location"]
    assert location.startswith("https://users.auth.example.test/oauth2/authorize?")
    q = _query(location)
    assert q["client_id"] == "users-client-id"
    assert q["code_challenge_method"] == "S256"
    with client.session_transaction() as sess:
        assert sess["login"]["pool"] == "user"
        assert sess["login"]["state"] == q["state"]
        assert sess["login"]["next"] == "/"


def test_admin_login_redirects_to_admin_pool(client):
    location = client.get("/admin/auth/login").headers["Location"]
    assert location.startswith("https://admins.auth.example.test/oauth2/authorize?")
    with client.session_transaction() as sess:
        assert sess["login"]["pool"] == "admin" and sess["login"]["next"] == "/admin"


@pytest.mark.parametrize(
    "next_value, stored",
    [("/account", "/account"), ("//evil.example/", "/admin"), ("https://evil.example/", "/admin")],
)
def test_next_path_must_be_relative(client, next_value, stored):
    client.get("/admin/auth/login", query_string={"next": next_value})
    with client.session_transaction() as sess:
        assert sess["login"]["next"] == stored


def test_user_callback_signs_in(client, http, key, clock):
    state, nonce = _start(client)
    _issue_tokens(http, key, "user", nonce, clock())
    resp = client.get("/auth/callback", query_string={"code": "code-1", "state": state})
    assert resp.status_code == 302 and resp.headers["Location"] == "/"
    url, form, auth = http.posts[0]
    assert url == "https://users.auth.example.test/oauth2/token"
    assert form["code"] == "code-1" and len(form["code_verifier"]) >= 43
    assert auth == ("users-client-id", "users-client-secret")
    with client.session_transaction() as sess:
        assert sess["sub"] == USER_SUB and sess["pool"] == "user"
        assert sess["email"] == "pat@example.com"
        assert "access_token" not in sess and "login" not in sess
        assert not any("never-stored" in str(v) for v in sess.values())
    assert client.get("/").get_data(as_text=True).count("0/5000 characters") == 1


def test_admin_callback_stores_access_token(client, http, key, clock):
    state, nonce = _start(client, "/admin/auth/login")
    _issue_tokens(http, key, "admin", nonce, clock())
    resp = client.get("/admin/auth/callback", query_string={"code": "c", "state": state})
    assert resp.status_code == 302 and resp.headers["Location"] == "/admin"
    assert http.posts[0][2] == ("admins-client-id", "admins-client-secret")
    with client.session_transaction() as sess:
        assert sess["pool"] == "admin" and sess["sub"] == ADMIN_SUB
        assert sess["access_token"].count(".") == 2
        assert sess["access_exp"] == int(clock()) + 3600


def test_callback_sets_cookie_flags(client, http, key, clock):
    state, nonce = _start(client)
    _issue_tokens(http, key, "user", nonce, clock())
    resp = client.get("/auth/callback", query_string={"code": "c", "state": state})
    cookie = resp.headers["Set-Cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Lax" in cookie


def _assert_failed(resp, client):
    assert resp.status_code == 400
    assert "Sign-in failed, try again." in resp.get_data(as_text=True)
    assert _signed_out(client)


def test_bad_state_fails_closed(client, http, key, clock):
    _, nonce = _start(client)
    _issue_tokens(http, key, "user", nonce, clock())
    resp = client.get("/auth/callback", query_string={"code": "c", "state": "forged"})
    _assert_failed(resp, client)
    assert http.posts == []


def test_state_is_single_use(client, http, key, clock):
    state, nonce = _start(client)
    _issue_tokens(http, key, "user", nonce, clock())
    client.get("/auth/callback", query_string={"code": "c", "state": state})
    client.post("/auth/logout", data={"csrf": csrf(client)})
    resp = client.get("/auth/callback", query_string={"code": "c", "state": state})
    _assert_failed(resp, client)


def test_callback_without_pending_login_fails(client):
    _assert_failed(client.get("/auth/callback", query_string={"code": "c", "state": "s"}), client)


def test_user_pending_login_cannot_finish_on_admin_callback(client, http, key, clock):
    state, nonce = _start(client, "/auth/login")
    _issue_tokens(http, key, "admin", nonce, clock())
    resp = client.get("/admin/auth/callback", query_string={"code": "c", "state": state})
    _assert_failed(resp, client)


def test_user_pool_token_on_admin_callback_fails(client, http, key, clock):
    state, nonce = _start(client, "/admin/auth/login")
    # The admin token endpoint hands back tokens issued for the user pool.
    _issue_tokens(http, key, "admin", nonce, clock(), claims_pool="user")
    resp = client.get("/admin/auth/callback", query_string={"code": "c", "state": state})
    _assert_failed(resp, client)


@pytest.mark.parametrize(
    "overrides",
    [{"exp": 1}, {"aud": "other-client"}, {"token_use": "access"}],
    ids=["expired", "aud", "token_use"],
)
def test_bad_id_token_fails_closed(client, http, key, clock, overrides):
    state, nonce = _start(client)
    _issue_tokens(http, key, "user", nonce, clock(), **overrides)
    _assert_failed(client.get("/auth/callback", query_string={"code": "c", "state": state}), client)


def test_wrong_nonce_fails_closed(client, http, key, clock):
    state, _ = _start(client)
    _issue_tokens(http, key, "user", "another-nonce", clock())
    _assert_failed(client.get("/auth/callback", query_string={"code": "c", "state": state}), client)


def test_managed_login_error_fails_closed(client):
    state, _ = _start(client)
    resp = client.get("/auth/callback", query_string={"error": "access_denied", "state": state})
    _assert_failed(resp, client)


def test_failed_callback_clears_existing_session(client, http, key, clock):
    sign_in(client)
    _assert_failed(client.get("/auth/callback", query_string={"code": "c", "state": "s"}), client)


@pytest.mark.parametrize(
    "pool, logout_prefix",
    [
        ("user", "https://users.auth.example.test/logout?"),
        ("admin", "https://admins.auth.example.test/logout?"),
    ],
)
def test_logout_clears_session_and_ends_managed_login(client, pool, logout_prefix):
    sign_in(client, pool=pool)
    resp = client.post("/auth/logout", data={"csrf": csrf(client)})
    assert resp.status_code == 302 and resp.headers["Location"].startswith(logout_prefix)
    assert _signed_out(client)


def test_logout_requires_csrf(client):
    sign_in(client)
    assert client.post("/auth/logout", data={"csrf": "wrong"}).status_code == 400
    assert client.post("/auth/logout").status_code == 400
    with client.session_transaction() as sess:
        assert sess["sub"] == USER_SUB


def test_logout_after_session_ended_goes_home(client, clock):
    # The 8-hour expiry cleared the session and its CSRF token.
    sign_in(client)
    clock.advance(8 * 3600)
    resp = client.post("/auth/logout", data={"csrf": "stale"})
    assert resp.status_code == 302 and resp.headers["Location"] == "/"


def test_session_ends_after_eight_hours(client, clock):
    sign_in(client)
    clock.advance(8 * 3600 - 1)  # the fake directory answers ACTIVE
    assert "0/5000 characters" in client.get("/").get_data(as_text=True)
    clock.advance(1)
    assert 'href="/auth/login"' in client.get("/").get_data(as_text=True)


def test_admin_session_can_use_the_app(client):
    sign_in(client, pool="admin")
    assert "0/5000 characters" in client.get("/").get_data(as_text=True)
    assert client.post("/transform", json={"text": "hi"}).status_code == 200


def test_no_revalidation_within_15_minutes(client, directory, clock):
    sign_in(client)
    clock.advance(899)
    client.get("/")
    assert directory.status_calls == []


@pytest.mark.parametrize("pool, sub", [("user", USER_SUB), ("admin", ADMIN_SUB)])
@pytest.mark.parametrize("status", [DISABLED, MISSING])
def test_disabled_or_deleted_account_signed_out_after_15_minutes(
    client, directory, clock, pool, sub, status
):
    sign_in(client, pool=pool)
    directory.statuses[(pool, sub)] = status
    clock.advance(900)
    assert 'href="/auth/login"' in client.get("/").get_data(as_text=True)
    assert directory.status_calls == [(pool, sub)]
    assert _signed_out(client)


def test_changed_email_signed_out_after_15_minutes(client, directory, clock):
    sign_in(client)
    directory.emails[("user", USER_SUB)] = "new@example.com"
    clock.advance(900)
    assert 'href="/auth/login"' in client.get("/").get_data(as_text=True)
    assert _signed_out(client)


def test_active_account_rechecked_every_15_minutes(client, directory, clock):
    sign_in(client)
    clock.advance(900)
    client.get("/")
    clock.advance(10)
    client.get("/")
    assert len(directory.status_calls) == 1


def test_throttled_revalidation_keeps_session(client, directory, clock):
    sign_in(client)
    directory.error = Throttled("TooManyRequestsException")
    clock.advance(900)
    assert "0/5000 characters" in client.get("/").get_data(as_text=True)
    client.get("/")
    assert len(directory.status_calls) == 2  # retried on the next request


def test_healthz_never_revalidates(client, directory, clock):
    sign_in(client)
    clock.advance(900)
    client.get("/healthz")
    assert directory.status_calls == []


def test_admin_cookie_stays_under_4kb(client, clock):
    # A random token larger than a real Cognito access token (~1,100 characters).
    sign_in(
        client,
        pool="admin",
        email="a.very.long.administrator.name@subdomain.example.com",
        given_name="Alexandra-Maximiliana",
        family_name="Featherstonehaugh-Worthington",
        access_token=".".join(secrets.token_urlsafe(n) for n in (60, 900, 256)),
    )
    cookie = client.get_cookie("session")
    assert cookie is not None and len(cookie.value) < 4096
