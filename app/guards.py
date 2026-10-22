"""View decorators: who may open a page, and the CSRF check on state-changing forms.

They read g.identity, which create_app's before_request hook sets on every request.
"""

import functools

from flask import abort, g, redirect, request, session, url_for

from app import session_auth


def _return_path() -> str | None:
    """The path to come back to after sign-in. A POST gets none, and sign-in
    lands on the pool's default page."""
    return request.path if request.method == "GET" else None


def sign_in_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if g.identity is None:
            return redirect(url_for("auth.login", next=_return_path()))
        return view(*args, **kwargs)

    return wrapper


def admin_required(view):
    """Admin-pool sessions only. A user-pool session gets 403."""

    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if g.identity is None:
            return redirect(url_for("auth.admin_login", next=_return_path()))
        if not g.identity.is_admin:
            abort(403)
        return view(*args, **kwargs)

    return wrapper


def csrf_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not session_auth.csrf_ok(session, request.form.get("csrf")):
            abort(400)
        return view(*args, **kwargs)

    return wrapper
