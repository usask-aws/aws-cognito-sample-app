import json
from datetime import datetime, timezone

import pytest

from app import directory as d
from tests.conftest import FakeDirectory, csrf, sign_in
from tests.oidc_fakes import ADMIN_SUB

TARGET = "33333333-3333-4333-8333-333333333333"
CREATED = datetime(2026, 10, 1, tzinfo=timezone.utc)


class AdminDirectory(FakeDirectory):
    """Records admin calls; raise errors[method] when set."""

    def __init__(self):
        super().__init__()
        self.calls = []
        self.errors = {}
        self.users = [d.DirectoryUser(TARGET, "pat@example.com", "Pat", "Example", True, CREATED)]
        self.next_page = None

    def _record(self, name, *args):
        self.calls.append((name, *args))
        if name in self.errors:
            raise self.errors[name]

    def invite(self, given_name, family_name, email):
        self._record("invite", given_name, family_name, email)
        return d.DirectoryUser(TARGET, email, given_name, family_name, True, CREATED)

    def list_users(self, page_token=None):
        self._record("list_users", page_token)
        return self.users, self.next_page

    def get_user(self, sub):
        self._record("get_user", sub)
        return self.users[0]

    def disable(self, sub):
        self._record("disable", sub)

    def enable(self, sub):
        self._record("enable", sub)

    def delete(self, sub):
        self._record("delete", sub)

    def change_email(self, sub, new_email):
        self._record("change_email", sub, new_email)


@pytest.fixture
def directory():
    return AdminDirectory()


@pytest.fixture
def audit():
    return []


@pytest.fixture
def client(make_app, directory, audit):
    return make_app(directory=directory, audit_lines=audit).test_client()


@pytest.fixture
def admin_client(client):
    return sign_in(client, pool="admin")


def _audit(audit):
    return [json.loads(line) for line in audit]


def _invite(c, **overrides):
    form = {"given_name": "Pat", "family_name": "Example", "email": "pat@example.com", "csrf": csrf(c)}
    form.update(overrides)
    return c.post("/admin/users", data=form)


def test_signed_out_admin_shows_admin_sign_in(client):
    resp = client.get("/admin")
    assert resp.status_code == 200
    assert 'href="/admin/auth/login"' in resp.get_data(as_text=True)


@pytest.mark.parametrize(
    "method, path",
    [
        ("get", "/admin"),
        ("post", "/admin/users"),
        ("get", f"/admin/users/{TARGET}/disable"),
        ("post", f"/admin/users/{TARGET}/enable"),
    ],
)
def test_user_pool_session_gets_403(client, directory, method, path):
    sign_in(client, pool="user")
    resp = getattr(client, method)(path, data={"csrf": csrf(client)})
    assert resp.status_code == 403
    assert not [c for c in directory.calls if c[0] != "list_users"]


def test_signed_out_post_redirects_to_admin_sign_in_without_next(client):
    # No next is carried for a POST.
    resp = client.post("/admin/users", data={})
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/admin/auth/login"


def test_dashboard_lists_users(admin_client, directory):
    directory.next_page = "page-2"
    html = admin_client.get("/admin").get_data(as_text=True)
    assert "pat@example.com" in html and "Pat Example" in html
    assert "Enabled" in html and "2026-10-01" in html
    assert "page=page-2" in html
    assert directory.calls == [("list_users", None)]
    assert admin_client.get("/admin?page=page-2").status_code == 200
    assert directory.calls[-1] == ("list_users", "page-2")


def test_dashboard_shows_list_error(admin_client, directory):
    directory.errors["list_users"] = d.Throttled("TooManyRequestsException")
    html = admin_client.get("/admin").get_data(as_text=True)
    assert "Try again shortly." in html


def test_admin_link_in_header_for_admins_only(client):
    admin = sign_in(client.application.test_client(), pool="admin")
    assert 'href="/admin"' in admin.get("/").get_data(as_text=True)
    user = sign_in(client.application.test_client(), pool="user")
    assert 'href="/admin"' not in user.get("/").get_data(as_text=True)


def test_invite(admin_client, directory, audit):
    resp = _invite(admin_client, given_name="  Pat ", email=" pat@example.com ")
    assert resp.status_code == 302
    assert ("invite", "Pat", "Example", "pat@example.com") in directory.calls
    assert "Invitation sent to pat@example.com." in admin_client.get("/admin").get_data(as_text=True)
    assert _audit(audit) == [
        {
            "event": "admin_action",
            "action": "invite",
            "admin_sub": ADMIN_SUB,
            "admin_email": "admin@example.com",
            "target_sub": TARGET,
            "target_email": "pat@example.com",
            "result": "ok",
            "timestamp": "2027-01-15T08:00:00+00:00",
        }
    ]


@pytest.mark.parametrize(
    "overrides, field_message",
    [
        ({"given_name": "   "}, "Enter a first name of 1 to 100 characters."),
        ({"family_name": "x" * 101}, "Enter a last name of 1 to 100 characters."),
        ({"given_name": "Pat\x00"}, "Enter a first name of 1 to 100 characters."),
        ({"email": "not-an-email"}, "Enter an email address like name@example.com."),
        ({"email": "a@b"}, "Enter an email address like name@example.com."),
    ],
)
def test_invite_validates_fields(admin_client, directory, audit, overrides, field_message):
    resp = _invite(admin_client, **overrides)
    assert resp.status_code == 400
    assert field_message in resp.get_data(as_text=True)
    assert not [c for c in directory.calls if c[0] == "invite"]
    assert audit == []


@pytest.mark.parametrize(
    "error, message",
    [
        (d.DuplicateUser("UsernameExistsException"), "A user with that email already exists."),
        (d.Throttled("TooManyRequestsException"), "Try again shortly."),
        (d.InvalidInput("InvalidParameterException"), "Cognito didn&#39;t accept those details."),
    ],
)
def test_invite_errors_are_shown_and_audited(admin_client, directory, audit, error, message):
    directory.errors["invite"] = error
    resp = _invite(admin_client)
    assert resp.status_code == 400
    assert message in resp.get_data(as_text=True)
    assert _audit(audit)[0]["result"] == type(error).__name__
    assert _audit(audit)[0]["target_email"] == "pat@example.com"


def test_invite_delivery_failure(admin_client, directory, audit):
    directory.errors["invite"] = d.DeliveryFailed("CodeDeliveryFailureException")
    _invite(admin_client)
    html = admin_client.get("/admin").get_data(as_text=True)
    assert "User created, but the invitation email could not be sent." in html
    assert "https://sarcastifyer.example.com/" in html
    assert _audit(audit)[0]["result"] == "DeliveryFailed"


def test_invite_requires_csrf(admin_client, directory):
    assert _invite(admin_client, csrf="wrong").status_code == 400
    assert not [c for c in directory.calls if c[0] == "invite"]


@pytest.mark.parametrize("action", ["disable", "delete", "email"])
def test_confirm_page_names_the_user(admin_client, action):
    html = admin_client.get(f"/admin/users/{TARGET}/{action}").get_data(as_text=True)
    assert "pat@example.com" in html


@pytest.mark.parametrize("action", ["disable", "delete"])
def test_destructive_action_needs_confirm(admin_client, directory, audit, action):
    resp = admin_client.post(f"/admin/users/{TARGET}/{action}", data={"csrf": csrf(admin_client)})
    assert resp.status_code == 200
    assert 'name="confirm" value="yes"' in resp.get_data(as_text=True)
    assert not [c for c in directory.calls if c[0] == action]
    assert audit == []


@pytest.mark.parametrize("action", ["disable", "enable", "delete"])
def test_action_runs_and_is_audited(admin_client, directory, audit, action):
    resp = admin_client.post(
        f"/admin/users/{TARGET}/{action}", data={"csrf": csrf(admin_client), "confirm": "yes"}
    )
    assert resp.status_code == 302
    assert (action, TARGET) in directory.calls
    line = _audit(audit)[0]
    assert (line["action"], line["result"], line["target_sub"], line["target_email"]) == (
        action,
        "ok",
        TARGET,
        "pat@example.com",
    )


def test_change_email_flow(admin_client, directory, audit):
    url = f"/admin/users/{TARGET}/email"
    token = csrf(admin_client)
    step1 = admin_client.post(url, data={"csrf": token, "new_email": "new@example.com"})
    html = step1.get_data(as_text=True)
    assert "from pat@example.com to new@example.com" in html
    assert not [c for c in directory.calls if c[0] == "change_email"]
    admin_client.post(url, data={"csrf": token, "new_email": "new@example.com", "confirm": "yes"})
    assert ("change_email", TARGET, "new@example.com") in directory.calls
    line = _audit(audit)[0]
    assert line["target_email"] == "new@example.com"
    assert line["previous_email"] == "pat@example.com"


def test_change_email_validates(admin_client, directory):
    resp = admin_client.post(
        f"/admin/users/{TARGET}/email",
        data={"csrf": csrf(admin_client), "new_email": "nope", "confirm": "yes"},
    )
    assert resp.status_code == 400
    assert not [c for c in directory.calls if c[0] == "change_email"]


def test_change_email_duplicate(admin_client, directory, audit):
    directory.errors["change_email"] = d.EmailInUse("AliasExistsException")
    admin_client.post(
        f"/admin/users/{TARGET}/email",
        data={"csrf": csrf(admin_client), "new_email": "taken@example.com", "confirm": "yes"},
    )
    assert "Another user already has that email." in admin_client.get("/admin").get_data(as_text=True)
    assert _audit(audit)[0]["result"] == "EmailInUse"


def test_action_failure_is_audited(admin_client, directory, audit):
    directory.errors["delete"] = d.UserNotFound("UserNotFoundException")
    admin_client.post(f"/admin/users/{TARGET}/delete", data={"csrf": csrf(admin_client), "confirm": "yes"})
    assert _audit(audit)[0]["result"] == "UserNotFound"
    assert "That user no longer exists." in admin_client.get("/admin").get_data(as_text=True)


def test_action_requires_csrf(admin_client, directory):
    resp = admin_client.post(f"/admin/users/{TARGET}/enable", data={"csrf": "x"})
    assert resp.status_code == 400
    assert not [c for c in directory.calls if c[0] == "enable"]


@pytest.mark.parametrize(
    "path",
    [
        f"/admin/users/{TARGET}/signout",
        f"/admin/users/{TARGET}/bogus",
        "/admin/users/not-a-sub/disable",
        "/admin/users/ABCDEF00-1111-4111-8111-111111111111/disable",
    ],
)
def test_unknown_action_or_bad_sub_is_404(admin_client, path):
    assert admin_client.post(path, data={"csrf": csrf(admin_client), "confirm": "yes"}).status_code == 404


def test_audit_lines_never_hold_tokens(admin_client, audit):
    _invite(admin_client)
    admin_client.post(f"/admin/users/{TARGET}/delete", data={"csrf": csrf(admin_client), "confirm": "yes"})
    with admin_client.session_transaction() as sess:
        secrets = [sess["access_token"], sess["csrf"]]
    for line in audit:
        assert not any(s in line for s in secrets)
