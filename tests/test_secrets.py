from unittest.mock import MagicMock, patch

from app import secrets


def setup_function():
    secrets.reset_cache()


def test_get_secret_returns_secret_string():
    fake_client = MagicMock()
    fake_client.get_secret_value.return_value = {"SecretString": "s3cr3t"}
    with patch("app.secrets.boto3.client", return_value=fake_client):
        assert secrets.get_secret("sarcastifyer/anthropic-api-key") == "s3cr3t"
    fake_client.get_secret_value.assert_called_once_with(SecretId="sarcastifyer/anthropic-api-key")


def test_get_secret_is_cached():
    fake_client = MagicMock()
    fake_client.get_secret_value.return_value = {"SecretString": "s3cr3t"}
    with patch("app.secrets.boto3.client", return_value=fake_client):
        secrets.get_secret("k")
        secrets.get_secret("k")
    fake_client.get_secret_value.assert_called_once()


def test_get_secret_raises_secret_not_found_when_missing():
    class ResourceNotFoundException(Exception):
        pass

    fake_client = MagicMock()
    fake_client.exceptions.ResourceNotFoundException = ResourceNotFoundException
    fake_client.get_secret_value.side_effect = ResourceNotFoundException("nope")
    with patch("app.secrets.boto3.client", return_value=fake_client):
        try:
            secrets.get_secret("sarcastifyer/anthropic-api-key")
        except secrets.SecretNotFoundError as exc:
            assert "sarcastifyer/anthropic-api-key" in str(exc)
        else:
            raise AssertionError("expected SecretNotFoundError")
