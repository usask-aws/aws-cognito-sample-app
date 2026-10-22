"""The signed-in session: what it holds, how long it lasts, and its CSRF token.

The session is Flask's signed cookie (signed, not encrypted). It never holds the
ID or refresh token, and only admin sessions hold an access token. Pages get the
signed-in identity from load_identity; nothing else reads the auth keys.
"""

import hmac
import secrets
from dataclasses import dataclass

from app.directory import ACTIVE, DirectoryError

USER = "user"
ADMIN = "admin"
POOLS = (USER, ADMIN)

_AUTH_KEYS = (
    "sub",
    "pool",
    "email",
    "given_name",
    "family_name",
    "auth_time",
    "checked_at",
    "access_token",
    "access_exp",
)
_PENDING = "login"
_CSRF = "csrf"
# Treat the access token as expired a minute early.
_ACCESS_TOKEN_MARGIN_SECONDS = 60


@dataclass(frozen=True)
class Identity:
    sub: str
    pool: str
    email: str
    given_name: str
    family_name: str

    @property
    def is_admin(self) -> bool:
        return self.pool == ADMIN

    @property
    def display_name(self) -> str:
        return f"{self.given_name} {self.family_name}".strip() or self.email


@dataclass(frozen=True)
class PendingLogin:
    """What the callback needs to finish a sign-in this browser started."""

    pool: str
    state: str
    nonce: str
    verifier: str
    next_path: str


def begin_login(sess, pending: PendingLogin) -> None:
    sess[_PENDING] = {
        "pool": pending.pool,
        "state": pending.state,
        "nonce": pending.nonce,
        "verifier": pending.verifier,
        "next": pending.next_path,
    }


def pop_pending(sess) -> PendingLogin | None:
    """Remove and return the sign-in in progress; each one is usable once."""
    data = sess.pop(_PENDING, None) if _PENDING in sess else None
    if not isinstance(data, dict):
        return None
    try:
        return PendingLogin(
            pool=data["pool"],
            state=data["state"],
            nonce=data["nonce"],
            verifier=data["verifier"],
            next_path=data["next"],
        )
    except KeyError:
        return None


def establish(
    sess,
    pool: str,
    claims: dict,
    now: float,
    access_token: str | None = None,
    access_exp: int | None = None,
) -> None:
    """Start a fresh session from verified ID-token claims."""
    if pool not in POOLS:
        raise ValueError(f"unknown pool {pool!r}")
    sess.clear()  # also drops any pending sign-in
    sess.permanent = True
    sess["sub"] = claims["sub"]
    sess["pool"] = pool
    sess["email"] = claims.get("email", "")
    sess["given_name"] = claims.get("given_name", "")
    sess["family_name"] = claims.get("family_name", "")
    sess["auth_time"] = int(now)
    sess["checked_at"] = int(now)
    if pool == ADMIN and access_token and access_exp:
        sess["access_token"] = access_token
        sess["access_exp"] = int(access_exp)
    sess[_CSRF] = secrets.token_urlsafe(32)


def load_identity(sess, now: float, lifetime: int) -> Identity | None:
    """The signed-in identity, or None. Expired sessions are cleared."""
    sub, pool = sess.get("sub"), sess.get("pool")
    if not isinstance(sub, str) or not sub or pool not in POOLS:
        # Not signed in. Drop stale auth keys but keep a sign-in in progress.
        for key in [k for k in _AUTH_KEYS if k in sess]:
            del sess[key]
        return None
    auth_time = sess.get("auth_time")
    if not isinstance(auth_time, int) or now - auth_time >= lifetime:
        sess.clear()
        return None
    return Identity(
        sub=sub,
        pool=pool,
        email=sess.get("email", ""),
        given_name=sess.get("given_name", ""),
        family_name=sess.get("family_name", ""),
    )


def needs_revalidation(sess, now: float, interval: int) -> bool:
    checked = sess.get("checked_at")
    return not isinstance(checked, int) or now - checked >= interval


def revalidate(sess, identity: Identity, now: float, directory, logger) -> Identity | None:
    """Re-check the account with Cognito. Disabled, deleted or a changed email
    (an admin's Change email) ends the session.

    A throttled or failed check keeps the session and retries on the next
    request.
    """
    try:
        status, email = directory.account_status(identity.pool, identity.sub)
    except DirectoryError as exc:
        logger.warning("session revalidation skipped: %s", type(exc).__name__)
        return identity
    if status != ACTIVE or email != identity.email:
        sess.clear()
        return None
    sess["checked_at"] = int(now)
    return identity


def admin_access_token(sess, now: float) -> str | None:
    """The admin's own access token for /account, or None if missing or expiring."""
    token, exp = sess.get("access_token"), sess.get("access_exp")
    if sess.get("pool") != ADMIN or not isinstance(token, str) or not isinstance(exp, int):
        return None
    if exp - _ACCESS_TOKEN_MARGIN_SECONDS <= now:
        return None
    return token


def csrf_token(sess) -> str:
    token = sess.get(_CSRF)
    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        sess[_CSRF] = token
    return token


def csrf_ok(sess, submitted) -> bool:
    expected = sess.get(_CSRF)
    return (
        isinstance(expected, str)
        and isinstance(submitted, str)
        and hmac.compare_digest(expected.encode(), submitted.encode())
    )


def safe_next(value, default: str) -> str:
    """A return path only if it's a relative path on this app."""
    if (
        isinstance(value, str)
        and value.startswith("/")
        and not value.startswith("//")
        and "\\" not in value
        and all(c.isprintable() and not c.isspace() for c in value)
    ):
        return value
    return default
