from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.transformer import MissingKeyTransformer, Transformer


def _fake_client(chunks, output_tokens):
    stream_obj = MagicMock()
    stream_obj.text_stream = iter(chunks)
    stream_obj.get_final_message.return_value = SimpleNamespace(
        usage=SimpleNamespace(output_tokens=output_tokens)
    )

    @contextmanager
    def stream_cm(**kwargs):
        stream_cm.captured = kwargs
        yield stream_obj

    client = SimpleNamespace(messages=SimpleNamespace(stream=stream_cm))
    return client, stream_cm


def test_yields_chunks_and_returns_token_count():
    client, _ = _fake_client(["Oh ", "sure, ", "great."], 12)
    t = Transformer(client, "claude-opus-4-8", 4096)

    gen = t.stream_transform("please help")
    collected = []
    try:
        while True:
            collected.append(next(gen))
    except StopIteration as stop:
        tokens = stop.value

    assert collected == ["Oh ", "sure, ", "great."]
    assert tokens == 12


def test_passes_model_prompt_and_user_text():
    client, stream_cm = _fake_client(["x"], 1)
    t = Transformer(client, "claude-opus-4-8", 4096)
    list(t.stream_transform("hello world"))

    kwargs = stream_cm.captured
    assert kwargs["model"] == "claude-opus-4-8"
    assert kwargs["max_tokens"] == 4096
    assert kwargs["messages"] == [{"role": "user", "content": "hello world"}]
    assert "thinking" not in kwargs
    assert "sarcastic" in kwargs["system"].lower()


def test_missing_key_transformer_yields_message_and_zero_tokens():
    t = MissingKeyTransformer("Missing Anthropic API key. Please check AWS Secret Manager.")

    gen = t.stream_transform("anything at all")
    collected = []
    try:
        while True:
            collected.append(next(gen))
    except StopIteration as stop:
        tokens = stop.value

    assert collected == ["Missing Anthropic API key. Please check AWS Secret Manager."]
    assert tokens == 0
