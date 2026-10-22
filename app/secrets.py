import functools

import boto3

from app import config


class SecretNotFoundError(Exception):
    """Raised when a Secrets Manager secret does not exist."""


@functools.lru_cache(maxsize=None)
def get_secret(name: str) -> str:
    client = boto3.client("secretsmanager", region_name=config.AWS_REGION)
    try:
        return client.get_secret_value(SecretId=name)["SecretString"]
    except client.exceptions.ResourceNotFoundException as exc:
        raise SecretNotFoundError(name) from exc


def reset_cache() -> None:
    get_secret.cache_clear()
