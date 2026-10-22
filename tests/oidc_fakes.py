"""Test doubles for sign-in: locally generated keys, a fake JWKS and token endpoint.

All values are synthetic (example.com addresses, made-up pool IDs).
"""

from joserfc import jwt
from joserfc.jwk import RSAKey

from app.oidc import PoolConfig

USER_SUB = "11111111-1111-4111-8111-111111111111"
ADMIN_SUB = "22222222-2222-4222-8222-222222222222"


def make_pools() -> dict[str, PoolConfig]:
    base = "https://app.example.test"
    return {
        "user": PoolConfig(
            name="user",
            region="ca-central-1",
            pool_id="ca-central-1_Users1",
            client_id="users-client-id",
            client_secret="users-client-secret",
            domain="users.auth.example.test",
            redirect_uri=f"{base}/auth/callback",
            logout_uri=f"{base}/",
            scopes=("openid", "email", "profile"),
        ),
        "admin": PoolConfig(
            name="admin",
            region="ca-central-1",
            pool_id="ca-central-1_Admins1",
            client_id="admins-client-id",
            client_secret="admins-client-secret",
            domain="admins.auth.example.test",
            redirect_uri=f"{base}/admin/auth/callback",
            logout_uri=f"{base}/admin",
            scopes=("openid", "email", "profile", "aws.cognito.signin.user.admin"),
        ),
    }


class SigningKey:
    """An RSA key pair standing in for a user pool's signing key."""

    def __init__(self, kid: str = "test-kid"):
        self.kid = kid
        self._key = RSAKey.generate_key(2048, parameters={"kid": kid})

    def jwk(self) -> dict:
        return self._key.as_dict(private=False)

    def sign(self, claims: dict, kid: str | None = None) -> str:
        return jwt.encode({"alg": "RS256", "kid": kid or self.kid}, claims, self._key)


def id_claims(pool: PoolConfig, nonce: str, now: float, **overrides) -> dict:
    claims = {
        "iss": pool.issuer,
        "aud": pool.client_id,
        "token_use": "id",
        "sub": ADMIN_SUB if pool.name == "admin" else USER_SUB,
        "email": "admin@example.com" if pool.name == "admin" else "pat@example.com",
        "given_name": "Pat",
        "family_name": "Example",
        "auth_time": int(now),
        "iat": int(now),
        "exp": int(now) + 3600,
        "nonce": nonce,
    }
    claims.update(overrides)
    return claims


def access_claims(pool: PoolConfig, now: float, **overrides) -> dict:
    claims = {
        "iss": pool.issuer,
        "client_id": pool.client_id,
        "token_use": "access",
        "sub": ADMIN_SUB if pool.name == "admin" else USER_SUB,
        "scope": " ".join(pool.scopes),
        "iat": int(now),
        "exp": int(now) + 3600,
    }
    claims.update(overrides)
    return claims


class FakeHttp:
    """Serves JWKS documents and token responses; records every call.

    jwks maps a JWKS URI to a document, or to a list of documents served in turn
    (the last one repeats). token_responses maps a token endpoint to its reply.
    """

    def __init__(self):
        self.jwks: dict[str, dict | list[dict]] = {}
        self.token_responses: dict[str, dict] = {}
        self.posts: list[tuple[str, dict, tuple[str, str]]] = []
        self.gets: list[str] = []

    def publish(self, pool: PoolConfig, *keys: SigningKey) -> None:
        self.jwks[pool.jwks_uri] = {"keys": [k.jwk() for k in keys]}

    def post_form(self, url, form, basic_auth):
        self.posts.append((url, dict(form), basic_auth))
        return self.token_responses[url]

    def get_json(self, url):
        self.gets.append(url)
        doc = self.jwks[url]
        if isinstance(doc, list):
            return doc.pop(0) if len(doc) > 1 else doc[0]
        return doc
