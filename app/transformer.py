from collections.abc import Generator

from app import config


class Transformer:
    def __init__(self, client, model: str, max_tokens: int):
        self._client = client
        self._model = model
        self._max_tokens = max_tokens

    def stream_transform(self, text: str) -> Generator[str, None, int]:
        with self._client.messages.stream(
            model=self._model,
            max_tokens=self._max_tokens,
            system=config.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": text}],
        ) as stream:
            for chunk in stream.text_stream:
                yield chunk
            return stream.get_final_message().usage.output_tokens


class MissingKeyTransformer:
    """Stand-in used when the Anthropic API key secret is absent.

    Every transform yields a fixed operator-facing message instead of calling
    the API, and records zero tokens. Same interface as Transformer.
    """

    def __init__(self, message: str):
        self._message = message

    def stream_transform(self, text: str) -> Generator[str, None, int]:
        yield self._message
        return 0
