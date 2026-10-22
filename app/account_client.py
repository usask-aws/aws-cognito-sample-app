"""Self-service MFA and password calls for /account.

Every call is authorized by the signed-in admin's own access token (scope
aws.cognito.signin.user.admin). Cognito errors map onto a few app errors.
"""

from dataclasses import dataclass

from botocore.exceptions import BotoCoreError, ClientError

TOTP = "SOFTWARE_TOKEN_MFA"
EMAIL = "EMAIL_OTP"
DEVICE_NAME = "Sarcastifyer"


class AccountError(Exception):
    """A self-service call failed. The message is the Cognito error code."""


class TokenRejected(AccountError):
    """The access token is expired or revoked: sign in again."""


class WrongCode(AccountError):
    pass


class WrongPassword(AccountError):
    pass


class PasswordRejected(AccountError):
    """The new password doesn't meet the pool's policy."""


class AccountThrottled(AccountError):
    pass


class FactorNotEnabled(AccountError):
    pass


@dataclass(frozen=True)
class MfaState:
    totp: bool
    email: bool
    preferred: str | None  # TOTP, EMAIL or None


class AccountClient:
    def __init__(self, client):
        self._client = client

    def mfa_state(self, token: str) -> MfaState:
        resp = self._call("get_user", AccessToken=token)
        enabled = set(resp.get("UserMFASettingList") or [])
        preferred = resp.get("PreferredMfaSetting")
        return MfaState(
            totp=TOTP in enabled,
            email=EMAIL in enabled,
            preferred=preferred if preferred in (TOTP, EMAIL) else None,
        )

    def begin_totp(self, token: str) -> str:
        """Start authenticator-app setup; returns the shared secret to show once."""
        return self._call("associate_software_token", AccessToken=token)["SecretCode"]

    def confirm_totp(self, token: str, code: str) -> None:
        resp = self._call(
            "verify_software_token",
            AccessToken=token,
            UserCode=code,
            FriendlyDeviceName=DEVICE_NAME,
        )
        if resp.get("Status") != "SUCCESS":
            raise WrongCode(resp.get("Status", "ERROR"))
        state = self.mfa_state(token)
        self._apply(token, totp=True, email=state.email, preferred=state.preferred)

    def remove_totp(self, token: str) -> None:
        state = self.mfa_state(token)
        self._apply(token, totp=False, email=state.email, preferred=state.preferred)

    def set_email_mfa(self, token: str, enabled: bool) -> None:
        state = self.mfa_state(token)
        self._apply(token, totp=state.totp, email=enabled, preferred=state.preferred)

    def set_preferred(self, token: str, factor: str) -> None:
        state = self.mfa_state(token)
        if (factor == TOTP and not state.totp) or (factor == EMAIL and not state.email):
            raise FactorNotEnabled(factor)
        self._apply(token, totp=state.totp, email=state.email, preferred=factor)

    def change_password(self, token: str, current: str, new: str) -> None:
        self._call(
            "change_password",
            AccessToken=token,
            PreviousPassword=current,
            ProposedPassword=new,
        )

    def _apply(self, token: str, *, totp: bool, email: bool, preferred: str | None) -> None:
        # Keep one factor preferred whenever any factor is on.
        if (preferred == TOTP and not totp) or (preferred == EMAIL and not email) or preferred is None:
            preferred = TOTP if totp else EMAIL if email else None
        self._call(
            "set_user_mfa_preference",
            AccessToken=token,
            SoftwareTokenMfaSettings={"Enabled": totp, "PreferredMfa": preferred == TOTP},
            EmailMfaSettings={"Enabled": email, "PreferredMfa": preferred == EMAIL},
        )

    def _call(self, operation: str, **kwargs) -> dict:
        try:
            return getattr(self._client, operation)(**kwargs)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            raise _map(operation, error.get("Code", ""), error.get("Message", "")) from exc
        except BotoCoreError as exc:
            raise AccountError(type(exc).__name__) from exc


def _map(operation: str, code: str, message: str) -> AccountError:
    if code == "NotAuthorizedException":
        # For ChangePassword, the message tells a wrong current password apart
        # from an expired token.
        if operation == "change_password" and "access token" not in message.lower():
            return WrongPassword(code)
        return TokenRejected(code)
    if code in ("CodeMismatchException", "EnableSoftwareTokenMFAException"):
        return WrongCode(code)
    if code == "InvalidPasswordException" or (
        operation == "change_password" and code == "InvalidParameterException"
    ):
        return PasswordRejected(code)
    if code in ("TooManyRequestsException", "LimitExceededException"):
        return AccountThrottled(code)
    return AccountError(code or "ClientError")
