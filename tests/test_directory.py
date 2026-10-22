from datetime import datetime, timezone

import boto3
import pytest
from botocore.stub import Stubber

from app import directory as d

USER_POOL = "ca-central-1_Users1"
ADMIN_POOL = "ca-central-1_Admins1"
SUB = "11111111-1111-4111-8111-111111111111"
CREATED = datetime(2026, 10, 1, tzinfo=timezone.utc)


@pytest.fixture
def stubbed():
    client = boto3.client(
        "cognito-idp",
        region_name="ca-central-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    with Stubber(client) as stubber:
        yield d.Directory(client, USER_POOL, ADMIN_POOL), stubber
        stubber.assert_no_pending_responses()


def _record(sub=SUB, email="pat@example.com", enabled=True, key="Attributes"):
    return {
        "Username": sub,
        key: [
            {"Name": "sub", "Value": sub},
            {"Name": "email", "Value": email},
            {"Name": "given_name", "Value": "Pat"},
            {"Name": "family_name", "Value": "Example"},
        ],
        "Enabled": enabled,
        "UserCreateDate": CREATED,
        "UserStatus": "CONFIRMED",
    }


def test_invite_creates_passwordless_user_and_emails_invitation(stubbed):
    directory, stubber = stubbed
    stubber.add_response(
        "admin_create_user",
        {"User": _record()},
        {
            "UserPoolId": USER_POOL,
            "Username": "pat@example.com",
            "UserAttributes": [
                {"Name": "given_name", "Value": "Pat"},
                {"Name": "family_name", "Value": "Example"},
                {"Name": "email", "Value": "pat@example.com"},
                {"Name": "email_verified", "Value": "true"},
            ],
            "DesiredDeliveryMediums": ["EMAIL"],
        },
    )
    user = directory.invite("Pat", "Example", "pat@example.com")
    assert user == d.DirectoryUser(SUB, "pat@example.com", "Pat", "Example", True, CREATED)


@pytest.mark.parametrize(
    "code, error",
    [
        ("UsernameExistsException", d.DuplicateUser),
        ("CodeDeliveryFailureException", d.DeliveryFailed),
        ("TooManyRequestsException", d.Throttled),
        ("LimitExceededException", d.Throttled),
        ("InvalidParameterException", d.InvalidInput),
        ("InternalErrorException", d.DirectoryError),
    ],
)
def test_invite_maps_cognito_errors(stubbed, code, error):
    directory, stubber = stubbed
    stubber.add_client_error("admin_create_user", service_error_code=code)
    with pytest.raises(error) as excinfo:
        directory.invite("Pat", "Example", "pat@example.com")
    assert str(excinfo.value) == code


def test_list_users_pages_by_60(stubbed):
    directory, stubber = stubbed
    stubber.add_response(
        "list_users",
        {"Users": [_record()], "PaginationToken": "page-2"},
        {"UserPoolId": USER_POOL, "Limit": 60},
    )
    stubber.add_response(
        "list_users",
        {"Users": []},
        {"UserPoolId": USER_POOL, "Limit": 60, "PaginationToken": "page-2"},
    )
    users, token = directory.list_users()
    assert [u.email for u in users] == ["pat@example.com"] and token == "page-2"
    assert directory.list_users("page-2") == ([], None)


def test_get_user_reads_user_pool(stubbed):
    directory, stubber = stubbed
    stubber.add_response(
        "admin_get_user",
        _record(key="UserAttributes"),
        {"UserPoolId": USER_POOL, "Username": SUB},
    )
    assert directory.get_user(SUB).email == "pat@example.com"


@pytest.mark.parametrize(
    "method, operation",
    [
        ("disable", "admin_disable_user"),
        ("enable", "admin_enable_user"),
        ("delete", "admin_delete_user"),
    ],
)
def test_simple_actions(stubbed, method, operation):
    directory, stubber = stubbed
    stubber.add_response(operation, {}, {"UserPoolId": USER_POOL, "Username": SUB})
    getattr(directory, method)(SUB)


def test_change_email_sets_verified_address(stubbed):
    directory, stubber = stubbed
    stubber.add_response(
        "admin_update_user_attributes",
        {},
        {
            "UserPoolId": USER_POOL,
            "Username": SUB,
            "UserAttributes": [
                {"Name": "email", "Value": "new@example.com"},
                {"Name": "email_verified", "Value": "true"},
            ],
        },
    )
    directory.change_email(SUB, "new@example.com")


def test_change_email_duplicate(stubbed):
    directory, stubber = stubbed
    stubber.add_client_error(
        "admin_update_user_attributes", service_error_code="AliasExistsException"
    )
    with pytest.raises(d.EmailInUse):
        directory.change_email(SUB, "taken@example.com")


@pytest.mark.parametrize("pool, pool_id", [("user", USER_POOL), ("admin", ADMIN_POOL)])
@pytest.mark.parametrize("enabled, status", [(True, d.ACTIVE), (False, d.DISABLED)])
def test_account_status(stubbed, pool, pool_id, enabled, status):
    directory, stubber = stubbed
    stubber.add_response(
        "admin_get_user",
        _record(enabled=enabled, key="UserAttributes"),
        {"UserPoolId": pool_id, "Username": SUB},
    )
    assert directory.account_status(pool, SUB) == (status, "pat@example.com")


def test_account_status_missing(stubbed):
    directory, stubber = stubbed
    stubber.add_client_error("admin_get_user", service_error_code="UserNotFoundException")
    assert directory.account_status("admin", SUB) == (d.MISSING, "")


def test_account_status_throttled_raises(stubbed):
    directory, stubber = stubbed
    stubber.add_client_error("admin_get_user", service_error_code="TooManyRequestsException")
    with pytest.raises(d.Throttled):
        directory.account_status("user", SUB)
