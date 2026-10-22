import boto3
import pytest
from botocore.stub import Stubber

from app import account_client as ac

TOKEN = "admin-access-token"


@pytest.fixture
def stubbed():
    client = boto3.client(
        "cognito-idp",
        region_name="ca-central-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    with Stubber(client) as stubber:
        yield ac.AccountClient(client), stubber
        stubber.assert_no_pending_responses()


def _get_user(stubber, enabled=(), preferred=None):
    resp = {
        "Username": "22222222-2222-4222-8222-222222222222",
        "UserAttributes": [{"Name": "email", "Value": "admin@example.com"}],
        "UserMFASettingList": list(enabled),
    }
    if preferred:
        resp["PreferredMfaSetting"] = preferred
    stubber.add_response("get_user", resp, {"AccessToken": TOKEN})


def _expect_preference(stubber, totp, totp_pref, email, email_pref):
    stubber.add_response(
        "set_user_mfa_preference",
        {},
        {
            "AccessToken": TOKEN,
            "SoftwareTokenMfaSettings": {"Enabled": totp, "PreferredMfa": totp_pref},
            "EmailMfaSettings": {"Enabled": email, "PreferredMfa": email_pref},
        },
    )


def test_mfa_state(stubbed):
    client, stubber = stubbed
    _get_user(stubber, enabled=[ac.TOTP, ac.EMAIL], preferred=ac.EMAIL)
    assert client.mfa_state(TOKEN) == ac.MfaState(totp=True, email=True, preferred=ac.EMAIL)


def test_mfa_state_none(stubbed):
    client, stubber = stubbed
    _get_user(stubber)
    assert client.mfa_state(TOKEN) == ac.MfaState(False, False, None)


def test_totp_setup_sequence(stubbed):
    client, stubber = stubbed
    stubber.add_response(
        "associate_software_token", {"SecretCode": "JBSWY3DPEHPK3PXP"}, {"AccessToken": TOKEN}
    )
    stubber.add_response(
        "verify_software_token",
        {"Status": "SUCCESS"},
        {"AccessToken": TOKEN, "UserCode": "123456", "FriendlyDeviceName": "Sarcastifyer"},
    )
    _get_user(stubber)
    _expect_preference(stubber, True, True, False, False)
    assert client.begin_totp(TOKEN) == "JBSWY3DPEHPK3PXP"
    client.confirm_totp(TOKEN, "123456")


def test_totp_added_keeps_email_preferred(stubbed):
    client, stubber = stubbed
    stubber.add_response("verify_software_token", {"Status": "SUCCESS"})
    _get_user(stubber, enabled=[ac.EMAIL], preferred=ac.EMAIL)
    _expect_preference(stubber, True, False, True, True)
    client.confirm_totp(TOKEN, "123456")


def test_totp_wrong_code(stubbed):
    client, stubber = stubbed
    stubber.add_client_error("verify_software_token", service_error_code="CodeMismatchException")
    with pytest.raises(ac.WrongCode):
        client.confirm_totp(TOKEN, "000000")


def test_totp_verify_status_error(stubbed):
    client, stubber = stubbed
    stubber.add_response("verify_software_token", {"Status": "ERROR"})
    with pytest.raises(ac.WrongCode):
        client.confirm_totp(TOKEN, "000000")


def test_remove_totp_moves_preference_to_email(stubbed):
    client, stubber = stubbed
    _get_user(stubber, enabled=[ac.TOTP, ac.EMAIL], preferred=ac.TOTP)
    _expect_preference(stubber, False, False, True, True)
    client.remove_totp(TOKEN)


def test_email_mfa_on_becomes_preferred(stubbed):
    client, stubber = stubbed
    _get_user(stubber)
    _expect_preference(stubber, False, False, True, True)
    client.set_email_mfa(TOKEN, True)


def test_email_mfa_off(stubbed):
    client, stubber = stubbed
    _get_user(stubber, enabled=[ac.EMAIL], preferred=ac.EMAIL)
    _expect_preference(stubber, False, False, False, False)
    client.set_email_mfa(TOKEN, False)


def test_set_preferred(stubbed):
    client, stubber = stubbed
    _get_user(stubber, enabled=[ac.TOTP, ac.EMAIL], preferred=ac.TOTP)
    _expect_preference(stubber, True, False, True, True)
    client.set_preferred(TOKEN, ac.EMAIL)


def test_set_preferred_requires_enabled_factor(stubbed):
    client, stubber = stubbed
    _get_user(stubber, enabled=[ac.EMAIL], preferred=ac.EMAIL)
    with pytest.raises(ac.FactorNotEnabled):
        client.set_preferred(TOKEN, ac.TOTP)


def test_change_password(stubbed):
    client, stubber = stubbed
    stubber.add_response(
        "change_password",
        {},
        {"AccessToken": TOKEN, "PreviousPassword": "Old-pass1!", "ProposedPassword": "New-pass1!"},
    )
    client.change_password(TOKEN, "Old-pass1!", "New-pass1!")


@pytest.mark.parametrize(
    "code, message, error",
    [
        ("NotAuthorizedException", "Incorrect username or password.", ac.WrongPassword),
        ("NotAuthorizedException", "Access Token has expired", ac.TokenRejected),
        ("InvalidPasswordException", "Password does not conform to policy", ac.PasswordRejected),
        ("InvalidParameterException", "1 validation error detected", ac.PasswordRejected),
        ("LimitExceededException", "Attempt limit exceeded", ac.AccountThrottled),
        ("InternalErrorException", "boom", ac.AccountError),
    ],
)
def test_change_password_errors(stubbed, code, message, error):
    client, stubber = stubbed
    stubber.add_client_error("change_password", service_error_code=code, service_message=message)
    with pytest.raises(error):
        client.change_password(TOKEN, "Old-pass1!", "New-pass1!")


def test_expired_token_on_other_calls(stubbed):
    client, stubber = stubbed
    stubber.add_client_error(
        "get_user", service_error_code="NotAuthorizedException", service_message="Access Token has expired"
    )
    with pytest.raises(ac.TokenRejected):
        client.mfa_state(TOKEN)
