"""OpenID Connect sign-in against a Cognito user pool's managed login.

Authorization code flow with PKCE and a confidential client. This module knows
nothing about Flask, pages or sessions: callers pass values in and get values
back, and every failure is an OidcError.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from threading import Lock

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import RSAKey

HTTP_TIMEOUT_SECONDS = 5


class OidcError(Exception):
    """Sign-in can't be completed. The message is for the log, never the user."""


@dataclass(frozen=True)
class PoolConfig:
    """One user pool and its app client, as the app sees them."""

    name: str  # "user" or "admin": the session's pool
    region: str
    pool_id: str
    client_id: str
    client_secret: str = field(repr=False)
    domain: str  # prefix domain, e.g. sarcastifyer-users.auth.ca-central-1.amazoncognito.com
    redirect_uri: str
    logout_uri: str
    scopes: tuple[str, ...]

    @property
    def issuer(self) -> str:
        return f"https://cognito-idp.{self.region}.amazonaws.com/{self.pool_id}"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/.well-known/jwks.json"

    @property
    def token_endpoint(self) -> str:
        return f"https://{self.domain}/oauth2/token"


@dataclass(frozen=True)
class LoginRequest:
    """The one-time values for a single sign-in attempt."""

    state: str
    nonce: str
    verifier: str = field(repr=False)


def new_login_request() -> LoginRequest:
    return LoginRequest(
        state=secrets.token_urlsafe(32),
        nonce=secrets.token_urlsafe(32),
        verifier=secrets.token_urlsafe(64),  # 86 characters; RFC 7636 allows 43-128
    )


def code_challenge(verifier: str) -> str:
    """The S256 PKCE challenge for a verifier (RFC 7636 section 4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def authorization_url(pool: PoolConfig, login: LoginRequest) -> str:
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": pool.client_id,
            "redirect_uri": pool.redirect_uri,
            "scope": " ".join(pool.scopes),
            "state": login.state,
            "nonce": login.nonce,
            "code_challenge": code_challenge(login.verifier),
            "code_challenge_method": "S256",
        }
    )
    return f"https://{pool.domain}/oauth2/authorize?{query}"


def logout_url(pool: PoolConfig) -> str:
    query = urllib.parse.urlencode(
        {"client_id": pool.client_id, "logout_uri": pool.logout_uri}
    )
    return f"https://{pool.domain}/logout?{query}"


class UrllibHttp:
    """The two HTTP calls sign-in makes."""

    def __init__(self, timeout: float = HTTP_TIMEOUT_SECONDS):
        self._timeout = timeout

    def post_form(self, url: str, form: dict, basic_auth: tuple[str, str]) -> dict:
        user, password = (urllib.parse.quote(v, safe="") for v in basic_auth)
        credentials = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
        request = urllib.request.Request(
            url,
            data=urllib.parse.urlencode(form).encode(),
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Authorization": f"Basic {credentials}",
            },
        )
        return self._json(request)

    def get_json(self, url: str) -> dict:
        return self._json(urllib.request.Request(url, headers={"Accept": "application/json"}))

    def _json(self, request: urllib.request.Request) -> dict:
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:  # noqa: S310
                body = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            # Log the status only, not the body.
            raise OidcError(f"{request.full_url} returned HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise OidcError(f"{request.full_url} failed: {type(exc).__name__}") from None
        if not isinstance(body, dict):
            raise OidcError(f"{request.full_url} returned a non-object")
        return body


class JwksCache:
    """Signing keys per pool, cached by kid. An unknown kid triggers one refetch."""

    def __init__(self, http):
        self._http = http
        self._keys: dict[str, dict[str, dict]] = {}  # jwks_uri -> kid -> JWK
        self._lock = Lock()

    def key(self, jwks_uri: str, kid: str) -> RSAKey:
        with self._lock:
            jwk = self._keys.get(jwks_uri, {}).get(kid)
        if jwk is None:
            fetched = self._http.get_json(jwks_uri).get("keys", [])
            keys = {
                k["kid"]: k
                for k in fetched
                if isinstance(k, dict) and isinstance(k.get("kid"), str)
            }
            with self._lock:
                self._keys[jwks_uri] = keys
            jwk = keys.get(kid)
        if jwk is None:
            raise OidcError(f"unknown signing key {kid!r}")
        try:
            return RSAKey.import_key(jwk)
        except (JoseError, ValueError, TypeError) as exc:
            raise OidcError(f"unusable signing key {kid!r}: {type(exc).__name__}") from None


class OidcClient:
    """Exchanges an authorization code and verifies the tokens Cognito returns."""

    def __init__(self, http, clock=time.time, leeway: int = 60):
        self._http = http
        self._jwks = JwksCache(http)
        self._clock = clock
        self._leeway = leeway

    def exchange_code(self, pool: PoolConfig, code: str, verifier: str) -> dict:
        tokens = self._http.post_form(
            pool.token_endpoint,
            {
                "grant_type": "authorization_code",
                "client_id": pool.client_id,
                "code": code,
                "redirect_uri": pool.redirect_uri,
                "code_verifier": verifier,
            },
            basic_auth=(pool.client_id, pool.client_secret),
        )
        if not isinstance(tokens.get("id_token"), str) or not isinstance(
            tokens.get("access_token"), str
        ):
            raise OidcError("token response is missing the ID or access token")
        return tokens

    def verify_id_token(self, pool: PoolConfig, token: str, nonce: str) -> dict:
        claims = self._verify(pool, token)
        if claims.get("aud") != pool.client_id:
            raise OidcError("ID token aud is not this pool's client")
        if claims.get("token_use") != "id":
            raise OidcError("token_use is not id")
        token_nonce = claims.get("nonce")
        if not isinstance(token_nonce, str) or not hmac.compare_digest(
            token_nonce.encode(), nonce.encode()
        ):
            raise OidcError("nonce mismatch")
        for name in ("sub", "email"):
            if not isinstance(claims.get(name), str) or not claims[name]:
                raise OidcError(f"ID token has no {name}")
        return claims

    def verify_access_token(self, pool: PoolConfig, token: str) -> dict:
        claims = self._verify(pool, token)
        if claims.get("client_id") != pool.client_id:
            raise OidcError("access token client_id is not this pool's client")
        if claims.get("token_use") != "access":
            raise OidcError("token_use is not access")
        return claims

    def _verify(self, pool: PoolConfig, token: str) -> dict:
        header = _unverified_header(token)
        if header.get("alg") != "RS256":
            raise OidcError(f"unexpected alg {header.get('alg')!r}")
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise OidcError("token has no kid")
        key = self._jwks.key(pool.jwks_uri, kid)
        try:
            claims = jwt.decode(token, key, algorithms=["RS256"]).claims
        except (JoseError, ValueError) as exc:
            raise OidcError(f"token rejected: {type(exc).__name__}") from None
        if claims.get("iss") != pool.issuer:
            raise OidcError("iss is not this pool")
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or exp + self._leeway < self._clock():
            raise OidcError("token expired")
        return claims


def _unverified_header(token) -> dict:
    """The JOSE header, read before verification only to pick the key."""
    if not isinstance(token, str) or token.count(".") != 2:
        raise OidcError("malformed token")
    segment = token.split(".", 1)[0]
    try:
        header = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except ValueError:
        raise OidcError("malformed token header") from None
    if not isinstance(header, dict):
        raise OidcError("malformed token header")
    return header
