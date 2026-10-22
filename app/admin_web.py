"""/admin: invite and manage user-pool accounts. Admin-pool sessions only.

Admins themselves are managed with the AWS CLI (see the runbook), never here.
Every action, including failures, writes one audit line.
"""

import re
import unicodedata

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from app import config
from app import directory as dirmod
from app.guards import admin_required, csrf_required

admin = Blueprint("admin", __name__)

SUB_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# A shape check only; Cognito does the final validation.
EMAIL_SHAPE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
MAX_NAME_CHARS = 100
MAX_EMAIL_CHARS = 254

CONFIRM_ACTIONS = ("disable", "delete", "email")
ACTIONS = CONFIRM_ACTIONS + ("enable",)

ERROR_MESSAGES = (
    (dirmod.DuplicateUser, "A user with that email already exists."),
    (dirmod.EmailInUse, "Another user already has that email."),
    (dirmod.UserNotFound, "That user no longer exists."),
    (dirmod.Throttled, "Try again shortly."),
    (dirmod.InvalidInput, "Cognito didn't accept those details. Check them and try again."),
)
GENERIC_ERROR = "Something went wrong. Try again; if it keeps happening, check the app log."
DONE_MESSAGES = {
    "disable": "{email} is disabled. Their app session ends within 15 minutes.",
    "enable": "{email} is enabled.",
    "delete": "{email} is deleted.",
    "email": "{email} now signs in as {new_email}.",
}


def _error_message(exc: Exception) -> str:
    return next((m for cls, m in ERROR_MESSAGES if isinstance(exc, cls)), GENERIC_ERROR)


def _clean_name(value) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not 1 <= len(value) <= MAX_NAME_CHARS:
        return None
    if any(unicodedata.category(c) == "Cc" for c in value):
        return None
    return value


def _clean_email(value) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if len(value) > MAX_EMAIL_CHARS or not EMAIL_SHAPE.fullmatch(value):
        return None
    return value


def _dashboard(form=None, errors=None, status=200):
    page = request.args.get("page") or None
    list_error = None
    try:
        users, next_page = current_app.extensions["directory"].list_users(page)
    except dirmod.DirectoryError as exc:
        current_app.logger.warning("listing users failed: %s", type(exc).__name__)
        users, next_page, list_error = [], None, _error_message(exc)
    return (
        render_template(
            "admin.html",
            users=users,
            next_page=next_page,
            list_error=list_error,
            form=form or {},
            errors=errors or {},
        ),
        status,
    )


@admin.get("/admin")
def dashboard():
    if g.identity is None:
        return render_template("admin_signin.html")
    if not g.identity.is_admin:
        abort(403)
    return _dashboard()


@admin.post("/admin/users")
@admin_required
@csrf_required
def invite():
    form = {k: request.form.get(k, "") for k in ("given_name", "family_name", "email")}
    given_name = _clean_name(form["given_name"])
    family_name = _clean_name(form["family_name"])
    email = _clean_email(form["email"])
    errors = {}
    if given_name is None:
        errors["given_name"] = "Enter a first name of 1 to 100 characters."
    if family_name is None:
        errors["family_name"] = "Enter a last name of 1 to 100 characters."
    if email is None:
        errors["email"] = "Enter an email address like name@example.com."
    if errors:
        return _dashboard(form, errors, 400)

    audit = current_app.extensions["audit"]
    try:
        user = current_app.extensions["directory"].invite(given_name, family_name, email)
    except dirmod.DeliveryFailed as exc:
        audit.admin_action(
            action="invite", admin=g.identity, result=type(exc).__name__, target_email=email
        )
        flash(
            "User created, but the invitation email could not be sent. They can still "
            f"sign in at {config.APP_BASE_URL}/.",
            "warning",
        )
        return redirect(url_for("admin.dashboard"))
    except dirmod.DirectoryError as exc:
        audit.admin_action(
            action="invite", admin=g.identity, result=type(exc).__name__, target_email=email
        )
        field = "email" if isinstance(exc, (dirmod.DuplicateUser, dirmod.InvalidInput)) else "form"
        return _dashboard(form, {field: _error_message(exc)}, 400)
    audit.admin_action(
        action="invite",
        admin=g.identity,
        result="ok",
        target_sub=user.sub,
        target_email=user.email,
    )
    flash(f"Invitation sent to {user.email}.", "success")
    return redirect(url_for("admin.dashboard"))


def _load_target(sub: str, action: str):
    """The target user, or a redirect back to the dashboard if it can't be read."""
    try:
        return current_app.extensions["directory"].get_user(sub), None
    except dirmod.DirectoryError as exc:
        current_app.extensions["audit"].admin_action(
            action=action, admin=g.identity, result=type(exc).__name__, target_sub=sub
        )
        flash(_error_message(exc), "error")
        return None, redirect(url_for("admin.dashboard"))


@admin.get("/admin/users/<sub>/<action>")
@admin_required
def confirm(sub, action):
    if action not in CONFIRM_ACTIONS or not SUB_PATTERN.fullmatch(sub):
        abort(404)
    user, bail = _load_target(sub, action)
    if bail:
        return bail
    return render_template("admin_confirm.html", user=user, action=action, new_email="", error=None)


@admin.post("/admin/users/<sub>/<action>")
@admin_required
@csrf_required
def act(sub, action):
    if action not in ACTIONS or not SUB_PATTERN.fullmatch(sub):
        abort(404)
    user, bail = _load_target(sub, action)
    if bail:
        return bail

    new_email = None
    if action == "email":
        new_email = _clean_email(request.form.get("new_email", ""))
        if new_email is None:
            return (
                render_template(
                    "admin_confirm.html",
                    user=user,
                    action=action,
                    new_email=request.form.get("new_email", ""),
                    error="Enter an email address like name@example.com.",
                ),
                400,
            )
    if action in CONFIRM_ACTIONS and request.form.get("confirm") != "yes":
        return render_template(
            "admin_confirm.html", user=user, action=action, new_email=new_email or "", error=None
        )

    directory = current_app.extensions["directory"]
    audit_fields = {"target_sub": sub, "target_email": new_email or user.email}
    if action == "email":
        audit_fields["previous_email"] = user.email
    try:
        if action == "disable":
            directory.disable(sub)
        elif action == "enable":
            directory.enable(sub)
        elif action == "delete":
            directory.delete(sub)
        else:
            directory.change_email(sub, new_email)
    except dirmod.DirectoryError as exc:
        current_app.extensions["audit"].admin_action(
            action=action, admin=g.identity, result=type(exc).__name__, **audit_fields
        )
        flash(_error_message(exc), "error")
        return redirect(url_for("admin.dashboard"))
    current_app.extensions["audit"].admin_action(
        action=action, admin=g.identity, result="ok", **audit_fields
    )
    flash(DONE_MESSAGES[action].format(email=user.email, new_email=new_email), "success")
    return redirect(url_for("admin.dashboard"))
