import urllib.parse

import pytest

from app import account_client as ac
from tests.conftest import csrf, sign_in


class FakeAccountClient:
    """Records self-service calls; raise errors[method] when set."""

    def __init__(self):
        self.calls = []
        self.errors = {}
        self.state = ac.MfaState(totp=False, email=False, preferred=None)

    def _record(self, name, *args):
        self.calls.append((name, *args))
        if name in self.errors:
            raise self.errors[name]

    def mfa_state(self, token):
        self._record("mfa_state", token)
        return self.state

    def begin_totp(self, token):
        self._record("begin_totp", token)
        return "JBSWY3DPEHPK3PXP"

    def confirm_totp(self, token, code):
        self._record("confirm_totp", token, code)

    def remove_totp(self, token):
        self._record("remove_totp", token)

    def set_email_mfa(self, token, enabled):
        self._record("set_email_mfa", token, enabled)

    def set_preferred(self, token, factor):
        self._record("set_preferred", token, factor)

    def change_password(self, token, current, new):
        self._record("change_password", token, current, new)


TOKEN = "aaa.bbb.ccc"


@pytest.fixture
def account():
    return FakeAccountClient()


@pytest.fixture
def client(make_app, account):
    return make_app(account_client=account).test_client()


@pytest.fixture
def admin_client(client):
    return sign_in(client, pool="admin", access_token=TOKEN)


def _post(c, action, **form):
    return c.post(f"/account/{action}", data={"csrf": csrf(c), **form})


def _assert_step_up(resp):
    assert resp.status_code == 302
    location = resp.headers["Location"]
    assert location.startswith("/admin/auth/login?")
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)["next"] == ["/account"]


def test_signed_out_redirects_to_admin_sign_in(client):
    resp = client.get("/account")
    assert resp.status_code == 302 and resp.headers["Location"].startswith("/admin/auth/login")


def test_user_pool_session_gets_403(client, account):
    sign_in(client, pool="user")
    assert client.get("/account").status_code == 403
    assert _post(client, "totp-begin").status_code == 403
    assert account.calls == []


def test_account_link_only_for_admins(client):
    user = sign_in(client.application.test_client(), pool="user")
    assert 'href="/account"' not in user.get("/").get_data(as_text=True)
    admin = sign_in(client.application.test_client(), pool="admin")
    assert 'href="/account"' in admin.get("/").get_data(as_text=True)


def test_page_shows_identity_and_factors(admin_client, account):
    account.state = ac.MfaState(totp=True, email=True, preferred=ac.TOTP)
    html = admin_client.get("/account").get_data(as_text=True)
    assert "admin@example.com" in html and "Pat Example" in html
    assert "Remove authenticator app" in html and "Turn off email codes" in html
    assert "Preferred factor" in html
    assert account.calls == [("mfa_state", TOKEN)]


@pytest.mark.parametrize("access_exp_offset", [None, 30])
def test_missing_or_expiring_access_token_steps_up(client, account, clock, access_exp_offset):
    if access_exp_offset is None:
        sign_in(client, pool="admin", access_token="")  # no token stored
    else:
        sign_in(client, pool="admin", access_token=TOKEN, access_exp=int(clock()) + access_exp_offset)
    _assert_step_up(client.get("/account"))
    _assert_step_up(_post(client, "totp-begin"))
    assert account.calls == []


def test_rejected_token_steps_up(admin_client, account):
    account.errors["mfa_state"] = ac.TokenRejected("NotAuthorizedException")
    _assert_step_up(admin_client.get("/account"))


def test_totp_setup_shows_qr_and_secret(admin_client, account):
    html = _post(admin_client, "totp-begin").get_data(as_text=True)
    assert "<svg" in html and "QR code for your authenticator app" in html
    assert "JBSWY3DPEHPK3PXP" in html
    assert account.calls[0] == ("begin_totp", TOKEN)


def test_totp_verify(admin_client, account):
    resp = _post(admin_client, "totp-verify", code=" 123456 ")
    assert resp.status_code == 302
    assert ("confirm_totp", TOKEN, "123456") in account.calls
    assert "Authenticator app added." in admin_client.get("/account").get_data(as_text=True)


@pytest.mark.parametrize("code", ["12345", "abcdef", "1234567", ""])
def test_totp_verify_rejects_badly_formed_code(admin_client, account, code):
    _post(admin_client, "totp-verify", code=code)
    assert not [c for c in account.calls if c[0] == "confirm_totp"]
    assert "That code didn" in admin_client.get("/account").get_data(as_text=True)


def test_totp_wrong_code(admin_client, account):
    account.errors["confirm_totp"] = ac.WrongCode("CodeMismatchException")
    _post(admin_client, "totp-verify", code="000000")
    assert "That code didn" in admin_client.get("/account").get_data(as_text=True)


def test_remove_totp(admin_client, account):
    _post(admin_client, "totp-remove")
    assert ("remove_totp", TOKEN) in account.calls


@pytest.mark.parametrize("action, enabled", [("email-mfa-on", True), ("email-mfa-off", False)])
def test_email_mfa_toggle(admin_client, account, action, enabled):
    _post(admin_client, action)
    assert ("set_email_mfa", TOKEN, enabled) in account.calls


@pytest.mark.parametrize("factor, value", [("totp", ac.TOTP), ("email", ac.EMAIL)])
def test_preferred_factor(admin_client, account, factor, value):
    _post(admin_client, "preferred", factor=factor)
    assert ("set_preferred", TOKEN, value) in account.calls


def test_preferred_factor_rejects_unknown(admin_client, account):
    _post(admin_client, "preferred", factor="sms")
    assert not [c for c in account.calls if c[0] == "set_preferred"]


def test_change_password(admin_client, account):
    _post(
        admin_client,
        "password",
        current_password="Old-pass1!",
        new_password="New-pass1!",
        confirm_password="New-pass1!",
    )
    assert ("change_password", TOKEN, "Old-pass1!", "New-pass1!") in account.calls
    assert "Password changed." in admin_client.get("/account").get_data(as_text=True)


def test_change_password_mismatch(admin_client, account):
    _post(admin_client, "password", current_password="a", new_password="B-pass1!x", confirm_password="other")
    assert not [c for c in account.calls if c[0] == "change_password"]
    assert "The new passwords don" in admin_client.get("/account").get_data(as_text=True)


@pytest.mark.parametrize(
    "error, message",
    [
        (ac.WrongPassword("NotAuthorizedException"), "Your current password is wrong."),
        (ac.PasswordRejected("InvalidPasswordException"), "That new password isn"),
        (ac.AccountThrottled("LimitExceededException"), "Too many attempts."),
    ],
)
def test_change_password_errors(admin_client, account, error, message):
    account.errors["change_password"] = error
    _post(admin_client, "password", current_password="a", new_password="b", confirm_password="b")
    assert message in admin_client.get("/account").get_data(as_text=True)


@pytest.mark.parametrize("action", ["totp-begin", "totp-remove", "email-mfa-on", "password"])
def test_actions_require_csrf(admin_client, account, action):
    resp = admin_client.post(f"/account/{action}", data={"csrf": "wrong"})
    assert resp.status_code == 400
    assert account.calls == []


def test_unknown_action_404(admin_client):
    assert _post(admin_client, "delete-account").status_code == 404
