"""Sign-in and sign-out routes for both pools.

Each pool has its own login and callback route, and the session's pool is set
from which callback ran, never from a request parameter.
"""

import hmac

from flask import (
    Blueprint,
    abort,
    current_app,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app import oidc, session_auth
from app.session_auth import ADMIN, USER

auth = Blueprint("auth", __name__)

_LOGIN_ENDPOINT = {USER: "auth.login", ADMIN: "auth.admin_login"}
_DEFAULT_NEXT = {USER: "/", ADMIN: "/admin"}


def _start(pool_name: str):
    pool = current_app.extensions["pools"][pool_name]
    login = oidc.new_login_request()
    session_auth.begin_login(
        session,
        session_auth.PendingLogin(
            pool=pool_name,
            state=login.state,
            nonce=login.nonce,
            verifier=login.verifier,
            next_path=session_auth.safe_next(request.args.get("next"), _DEFAULT_NEXT[pool_name]),
        ),
    )
    return redirect(oidc.authorization_url(pool, login))


def _complete(pool_name: str):
    pending = session_auth.pop_pending(session)
    pool = current_app.extensions["pools"][pool_name]
    client = current_app.extensions["oidc"]
    try:
        if pending is None or pending.pool != pool_name:
            raise oidc.OidcError("no sign-in in progress for this pool")
        if "error" in request.args:
            raise oidc.OidcError(f"managed login returned error {request.args['error'][:64]!r}")
        code, state = request.args.get("code", ""), request.args.get("state", "")
        if not code or not hmac.compare_digest(state.encode(), pending.state.encode()):
            raise oidc.OidcError("state mismatch")
        tokens = client.exchange_code(pool, code, pending.verifier)
        claims = client.verify_id_token(pool, tokens["id_token"], pending.nonce)
        access_token = access_exp = None
        if pool_name == ADMIN:
            access = client.verify_access_token(pool, tokens["access_token"])
            if access.get("sub") != claims["sub"]:
                raise oidc.OidcError("ID and access tokens are for different users")
            access_token, access_exp = tokens["access_token"], access["exp"]
    except oidc.OidcError as exc:
        session.clear()
        current_app.logger.warning("sign-in failed (%s pool): %s", pool_name, exc)
        return (
            render_template(
                "error.html",
                title="Sign-in failed",
                message="Sign-in failed, try again.",
                retry_url=url_for(_LOGIN_ENDPOINT[pool_name]),
            ),
            400,
        )
    session_auth.establish(
        session, pool_name, claims, current_app.extensions["clock"](), access_token, access_exp
    )
    return redirect(pending.next_path)


@auth.get("/auth/login")
def login():
    return _start(USER)


@auth.get("/auth/callback")
def callback():
    return _complete(USER)


@auth.get("/admin/auth/login")
def admin_login():
    return _start(ADMIN)


@auth.get("/admin/auth/callback")
def admin_callback():
    return _complete(ADMIN)


@auth.post("/auth/logout")
def logout():
    """End the app session, then Cognito's managed-login session for that pool."""
    if g.identity is None:
        # Already ended (8-hour expiry or revalidation): redirect home without a
        # CSRF check.
        return redirect(url_for("main.index"))
    if not session_auth.csrf_ok(session, request.form.get("csrf")):
        abort(400)
    pool = current_app.extensions["pools"][g.identity.pool]
    session.clear()
    return redirect(oidc.logout_url(pool))
