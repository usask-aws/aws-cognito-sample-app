import base64
import json
import urllib.parse

import pytest

from app import oidc
from tests.oidc_fakes import (
    FakeHttp,
    SigningKey,
    access_claims,
    id_claims,
    make_pools,
)

NOW = 1_800_000_000.0
NONCE = "nonce-123"


@pytest.fixture(scope="module")
def key():
    return SigningKey("kid-1")


@pytest.fixture(scope="module")
def other_key():
    return SigningKey("kid-1")  # same kid, different key: a forged signature


@pytest.fixture
def pools():
    return make_pools()


@pytest.fixture
def http(pools, key):
    fake = FakeHttp()
    fake.publish(pools["user"], key)
    fake.publish(pools["admin"], key)
    return fake


@pytest.fixture
def client(http):
    return oidc.OidcClient(http, clock=lambda: NOW, leeway=60)


def _query(url):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))


def test_code_challenge_matches_rfc7636_example():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert oidc.code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_new_login_request_values_are_random_and_long_enough():
    a, b = oidc.new_login_request(), oidc.new_login_request()
    assert a.state != b.state and a.nonce != b.nonce and a.verifier != b.verifier
    assert 43 <= len(a.verifier) <= 128


def test_authorization_url_for_pool(pools):
    login = oidc.LoginRequest(state="s1", nonce="n1", verifier="v" * 50)
    url = oidc.authorization_url(pools["admin"], login)
    assert url.startswith("https://admins.auth.example.test/oauth2/authorize?")
    q = _query(url)
    assert q == {
        "response_type": "code",
        "client_id": "admins-client-id",
        "redirect_uri": "https://app.example.test/admin/auth/callback",
        "scope": "openid email profile aws.cognito.signin.user.admin",
        "state": "s1",
        "nonce": "n1",
        "code_challenge": oidc.code_challenge("v" * 50),
        "code_challenge_method": "S256",
    }
    assert "v" * 50 not in url  # the verifier never leaves the server


def test_logout_url(pools):
    url = oidc.logout_url(pools["user"])
    assert url.startswith("https://users.auth.example.test/logout?")
    assert _query(url) == {
        "client_id": "users-client-id",
        "logout_uri": "https://app.example.test/",
    }


def test_pool_repr_hides_client_secret(pools):
    assert "users-client-secret" not in repr(pools["user"])


def test_exchange_code_sends_verifier_and_client_secret(client, http, pools):
    pool = pools["user"]
    http.token_responses[pool.token_endpoint] = {"id_token": "i", "access_token": "a"}
    tokens = client.exchange_code(pool, "code-1", "verifier-1")
    assert tokens == {"id_token": "i", "access_token": "a"}
    assert http.posts == [
        (
            "https://users.auth.example.test/oauth2/token",
            {
                "grant_type": "authorization_code",
                "client_id": "users-client-id",
                "code": "code-1",
                "redirect_uri": "https://app.example.test/auth/callback",
                "code_verifier": "verifier-1",
            },
            ("users-client-id", "users-client-secret"),
        )
    ]


def test_exchange_code_requires_both_tokens(client, http, pools):
    pool = pools["user"]
    http.token_responses[pool.token_endpoint] = {"access_token": "a"}
    with pytest.raises(oidc.OidcError):
        client.exchange_code(pool, "code-1", "verifier-1")


def test_verify_id_token_returns_claims(client, key, pools):
    pool = pools["user"]
    claims = client.verify_id_token(pool, key.sign(id_claims(pool, NONCE, NOW)), NONCE)
    assert claims["sub"] == "11111111-1111-4111-8111-111111111111"
    assert claims["email"] == "pat@example.com"


@pytest.mark.parametrize(
    "overrides",
    [
        {"exp": int(NOW) - 61},
        {"iss": "https://cognito-idp.ca-central-1.amazonaws.com/ca-central-1_Other"},
        {"aud": "some-other-client"},
        {"token_use": "access"},
        {"sub": ""},
        {"email": None},
    ],
    ids=["expired", "iss", "aud", "token_use", "no-sub", "no-email"],
)
def test_verify_id_token_rejects_bad_claims(client, key, pools, overrides):
    pool = pools["user"]
    token = key.sign(id_claims(pool, NONCE, NOW, **overrides))
    with pytest.raises(oidc.OidcError):
        client.verify_id_token(pool, token, NONCE)


def test_verify_id_token_rejects_wrong_nonce(client, key, pools):
    pool = pools["user"]
    token = key.sign(id_claims(pool, "other-nonce", NOW))
    with pytest.raises(oidc.OidcError):
        client.verify_id_token(pool, token, NONCE)


def test_verify_id_token_allows_small_clock_skew(client, key, pools):
    pool = pools["user"]
    token = key.sign(id_claims(pool, NONCE, NOW, exp=int(NOW) - 30))
    assert client.verify_id_token(pool, token, NONCE)["sub"]


def test_verify_id_token_rejects_bad_signature(client, other_key, pools):
    pool = pools["user"]
    with pytest.raises(oidc.OidcError):
        client.verify_id_token(pool, other_key.sign(id_claims(pool, NONCE, NOW)), NONCE)


def test_unknown_kid_refetches_once_then_fails(client, http, key, pools):
    pool = pools["user"]
    token = key.sign(id_claims(pool, NONCE, NOW), kid="kid-rotated")
    with pytest.raises(oidc.OidcError):
        client.verify_id_token(pool, token, NONCE)
    assert http.gets == [pool.jwks_uri]


def test_unknown_kid_refetch_picks_up_rotated_key(http, key, pools):
    pool = pools["user"]
    rotated = SigningKey("kid-2")
    http.jwks[pool.jwks_uri] = [{"keys": [key.jwk()]}, {"keys": [key.jwk(), rotated.jwk()]}]
    client = oidc.OidcClient(http, clock=lambda: NOW)
    client.verify_id_token(pool, key.sign(id_claims(pool, NONCE, NOW)), NONCE)
    client.verify_id_token(pool, rotated.sign(id_claims(pool, NONCE, NOW)), NONCE)
    assert http.gets == [pool.jwks_uri, pool.jwks_uri]


def test_keys_are_cached(client, http, key, pools):
    pool = pools["user"]
    for _ in range(3):
        client.verify_id_token(pool, key.sign(id_claims(pool, NONCE, NOW)), NONCE)
    assert http.gets == [pool.jwks_uri]


def _unsigned(header: dict, claims: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc(header)}.{enc(claims)}."


@pytest.mark.parametrize(
    "token",
    [
        "not-a-jwt",
        "a.b",
        "!!!.e30.sig",
        None,
    ],
)
def test_malformed_tokens_rejected(client, pools, token):
    with pytest.raises(oidc.OidcError):
        client.verify_id_token(pools["user"], token, NONCE)


def test_alg_none_rejected(client, pools):
    pool = pools["user"]
    token = _unsigned({"alg": "none", "kid": "kid-1"}, id_claims(pool, NONCE, NOW))
    with pytest.raises(oidc.OidcError):
        client.verify_id_token(pool, token, NONCE)


def test_user_pool_token_fails_for_admin_pool(client, key, pools):
    # Both pools publish the same key here, so only the iss/aud checks stop it.
    token = key.sign(id_claims(pools["user"], NONCE, NOW))
    with pytest.raises(oidc.OidcError):
        client.verify_id_token(pools["admin"], token, NONCE)


def test_verify_access_token(client, key, pools):
    pool = pools["admin"]
    claims = client.verify_access_token(pool, key.sign(access_claims(pool, NOW)))
    assert claims["token_use"] == "access"


@pytest.mark.parametrize(
    "overrides",
    [{"client_id": "users-client-id"}, {"token_use": "id"}, {"exp": int(NOW) - 120}],
    ids=["client_id", "token_use", "expired"],
)
def test_verify_access_token_rejects_bad_claims(client, key, pools, overrides):
    pool = pools["admin"]
    with pytest.raises(oidc.OidcError):
        client.verify_access_token(pool, key.sign(access_claims(pool, NOW, **overrides)))
