"""Cognito user-pool administration for /admin, and account checks for sessions.

A thin wrapper over the cognito-idp Admin* calls. It returns plain values and
maps Cognito errors onto a few app errors. Users are addressed by sub, which is
the internal username in an email-username pool.
"""

from dataclasses import dataclass
from datetime import datetime

from botocore.exceptions import BotoCoreError, ClientError

ACTIVE = "active"
DISABLED = "disabled"
MISSING = "missing"

PAGE_SIZE = 60  # ListUsers maximum


class DirectoryError(Exception):
    """A Cognito call failed. The message is the Cognito error code."""


class DuplicateUser(DirectoryError):
    pass


class EmailInUse(DirectoryError):
    pass


class UserNotFound(DirectoryError):
    pass


class Throttled(DirectoryError):
    pass


class DeliveryFailed(DirectoryError):
    pass


class InvalidInput(DirectoryError):
    pass


_ERRORS = {
    "UsernameExistsException": DuplicateUser,
    "AliasExistsException": EmailInUse,
    "UserNotFoundException": UserNotFound,
    "TooManyRequestsException": Throttled,
    "LimitExceededException": Throttled,
    "CodeDeliveryFailureException": DeliveryFailed,
    "InvalidParameterException": InvalidInput,
}


@dataclass(frozen=True)
class DirectoryUser:
    sub: str
    email: str
    given_name: str
    family_name: str
    enabled: bool
    created: datetime | None


def _user(record: dict, attributes_key: str = "Attributes") -> DirectoryUser:
    attrs = {a["Name"]: a.get("Value", "") for a in record.get(attributes_key, [])}
    return DirectoryUser(
        sub=attrs.get("sub") or record["Username"],
        email=attrs.get("email", ""),
        given_name=attrs.get("given_name", ""),
        family_name=attrs.get("family_name", ""),
        enabled=bool(record.get("Enabled", False)),
        created=record.get("UserCreateDate"),
    )


class Directory:
    def __init__(self, client, user_pool_id: str, admin_pool_id: str):
        self._client = client
        self._user_pool = user_pool_id
        self._pools = {"user": user_pool_id, "admin": admin_pool_id}

    def invite(self, given_name: str, family_name: str, email: str) -> DirectoryUser:
        """Create a passwordless user; Cognito emails the invitation."""
        resp = self._call(
            "admin_create_user",
            UserPoolId=self._user_pool,
            Username=email,
            UserAttributes=[
                {"Name": "given_name", "Value": given_name},
                {"Name": "family_name", "Value": family_name},
                {"Name": "email", "Value": email},
                {"Name": "email_verified", "Value": "true"},
            ],
            DesiredDeliveryMediums=["EMAIL"],
        )
        return _user(resp["User"])

    def list_users(self, page_token: str | None = None) -> tuple[list[DirectoryUser], str | None]:
        kwargs = {"UserPoolId": self._user_pool, "Limit": PAGE_SIZE}
        if page_token:
            kwargs["PaginationToken"] = page_token
        resp = self._call("list_users", **kwargs)
        return [_user(u) for u in resp.get("Users", [])], resp.get("PaginationToken")

    def get_user(self, sub: str) -> DirectoryUser:
        resp = self._call("admin_get_user", UserPoolId=self._user_pool, Username=sub)
        return _user(resp, attributes_key="UserAttributes")

    def disable(self, sub: str) -> None:
        """Block sign-in. AdminDisableUser also revokes the user's tokens."""
        self._call("admin_disable_user", UserPoolId=self._user_pool, Username=sub)

    def enable(self, sub: str) -> None:
        self._call("admin_enable_user", UserPoolId=self._user_pool, Username=sub)

    def delete(self, sub: str) -> None:
        self._call("admin_delete_user", UserPoolId=self._user_pool, Username=sub)

    def change_email(self, sub: str, new_email: str) -> None:
        """The new address becomes the sign-in name and receives sign-in codes."""
        self._call(
            "admin_update_user_attributes",
            UserPoolId=self._user_pool,
            Username=sub,
            UserAttributes=[
                {"Name": "email", "Value": new_email},
                {"Name": "email_verified", "Value": "true"},
            ],
        )

    def account_status(self, pool: str, sub: str) -> tuple[str, str]:
        """(ACTIVE, DISABLED or MISSING; current email). Throttling and other failures raise."""
        try:
            resp = self._call("admin_get_user", UserPoolId=self._pools[pool], Username=sub)
        except UserNotFound:
            return MISSING, ""
        user = _user(resp, attributes_key="UserAttributes")
        return (ACTIVE if user.enabled else DISABLED), user.email

    def _call(self, operation: str, **kwargs) -> dict:
        try:
            return getattr(self._client, operation)(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            raise _ERRORS.get(code, DirectoryError)(code or "ClientError") from exc
        except BotoCoreError as exc:
            raise DirectoryError(type(exc).__name__) from exc
