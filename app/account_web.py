"""/account: an admin's own MFA factors and password. Admin-pool sessions only.

Calls use the admin's own access token from the session. When it's missing or
about to expire, the admin is sent back through admin sign-in (step-up).
"""

import re
import urllib.parse

import segno
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup

from app import account_client as ac
from app import session_auth
from app.guards import admin_required, csrf_required

account = Blueprint("account", __name__)

ISSUER = "Sarcastifyer"
CODE_PATTERN = re.compile(r"[0-9]{6}")
FACTORS = {"totp": ac.TOTP, "email": ac.EMAIL}
ACTIONS = (
    "totp-begin",
    "totp-verify",
    "totp-remove",
    "email-mfa-on",
    "email-mfa-off",
    "preferred",
    "password",
)
DONE_MESSAGES = {
    "totp-verify": "Authenticator app added. You'll be asked for a code at your next sign-in.",
    "totp-remove": "Authenticator app removed.",
    "email-mfa-on": "Email codes turned on. You'll be asked for a code at your next sign-in.",
    "email-mfa-off": "Email codes turned off.",
    "preferred": "Preferred sign-in factor updated.",
    "password": "Password changed.",
}
ERROR_MESSAGES = (
    (ac.WrongCode, "That code didn't match. Choose Set up again and scan the new code."),
    (ac.WrongPassword, "Your current password is wrong."),
    (
        ac.PasswordRejected,
        "That new password isn't allowed. Use at least 8 characters with upper and lower "
        "case letters, a number and a symbol.",
    ),
    (ac.AccountThrottled, "Too many attempts. Try again shortly."),
    (ac.FactorNotEnabled, "Turn that factor on before making it preferred."),
)
GENERIC_ERROR = "Something went wrong. Try again; if it keeps happening, check the app log."


def _token() -> str | None:
    return session_auth.admin_access_token(session, current_app.extensions["clock"]())


def _step_up():
    return redirect(url_for("auth.admin_login", next=url_for("account.index")))


def _totp_view(secret: str) -> dict:
    label = urllib.parse.quote(f"{ISSUER}:{g.identity.email}")
    uri = f"otpauth://totp/{label}?" + urllib.parse.urlencode({"secret": secret, "issuer": ISSUER})
    svg = segno.make(uri, error="m").svg_inline(scale=4, title="QR code for your authenticator app")
    return {"secret": secret, "uri": uri, "qr_svg": Markup(svg)}


def _render(state, totp=None):
    return render_template("account.html", state=state, totp=totp)


@account.get("/account")
@admin_required
def index():
    token = _token()
    if token is None:
        return _step_up()
    client = current_app.extensions["account_client"]
    try:
        state = client.mfa_state(token)
    except ac.TokenRejected:
        return _step_up()
    except ac.AccountError as exc:
        current_app.logger.warning("reading MFA settings failed: %s", type(exc).__name__)
        flash("Couldn't load your sign-in settings. Try again shortly.", "error")
        state = None
    return _render(state)


@account.post("/account/<action>")
@admin_required
@csrf_required
def act(action):
    if action not in ACTIONS:
        abort(404)
    token = _token()
    if token is None:
        return _step_up()
    client = current_app.extensions["account_client"]
    try:
        if action == "totp-begin":
            secret = client.begin_totp(token)
            return _render(client.mfa_state(token), _totp_view(secret))
        if action == "totp-verify":
            code = request.form.get("code", "").strip()
            if not CODE_PATTERN.fullmatch(code):
                raise ac.WrongCode("bad format")
            client.confirm_totp(token, code)
        elif action == "totp-remove":
            client.remove_totp(token)
        elif action in ("email-mfa-on", "email-mfa-off"):
            client.set_email_mfa(token, action == "email-mfa-on")
        elif action == "preferred":
            factor = FACTORS.get(request.form.get("factor", ""))
            if factor is None:
                raise ac.FactorNotEnabled("unknown factor")
            client.set_preferred(token, factor)
        else:
            current = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            if new != request.form.get("confirm_password", ""):
                flash("The new passwords don't match.", "error")
                return redirect(url_for("account.index"))
            client.change_password(token, current, new)
    except ac.TokenRejected:
        return _step_up()
    except ac.AccountError as exc:
        current_app.logger.warning("account action %s failed: %s", action, type(exc).__name__)
        flash(next((m for cls, m in ERROR_MESSAGES if isinstance(exc, cls)), GENERIC_ERROR), "error")
        return redirect(url_for("account.index"))
    flash(DONE_MESSAGES[action], "success")
    return redirect(url_for("account.index"))
