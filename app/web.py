import json

from flask import (
    Blueprint,
    Response,
    current_app,
    g,
    render_template,
    request,
    stream_with_context,
)

from app import config
from app.mailer import build_body

main = Blueprint("main", __name__)


@main.get("/healthz")
def healthz():
    return {"status": "ok"}, 200


@main.get("/")
def index():
    if g.identity is None:
        return render_template("landing.html")
    return render_template("index.html", max_chars=config.MAX_INPUT_CHARS)


@main.post("/transform")
def transform():
    if g.identity is None:
        return {"error": "unauthorized"}, 401

    payload = request.get_json(silent=True) or {}
    text = payload.get("text", "")
    if not isinstance(text, str):
        return {"error": "Invalid input."}, 400
    if len(text) > config.MAX_INPUT_CHARS:
        return {"error": f"Input exceeds {config.MAX_INPUT_CHARS} characters."}, 413

    # The result only ever goes to the signed-in user's own address; any
    # address the client sends is ignored.
    email_me = payload.get("email", False)
    if not isinstance(email_me, bool):
        return {"error": "Invalid input."}, 400
    recipient = g.identity.email

    rate_limiter = current_app.extensions["rate_limiter"]
    # Keyed on the Cognito sub.
    if not rate_limiter.allow(g.identity.sub):
        return {"error": "Rate limit exceeded. Try again in a minute."}, 429

    token_brake = current_app.extensions["token_brake"]
    if token_brake.exceeded():
        return {"error": "Daily usage limit reached. Try again tomorrow."}, 429

    transformer = current_app.extensions["transformer"]
    mailer = current_app.extensions["mailer"]

    def send_result(result: str) -> str:
        """Email input + result to the signed-in user; return the line to append."""
        try:
            mailer.send(recipient, config.EMAIL_SUBJECT, build_body(text, result))
        except Exception:  # noqa: BLE001
            current_app.logger.exception("email send failed")
            return f"\nEmail could not be sent to {recipient}"
        return f"\nEmail was sent to {recipient}"

    def event_stream():
        gen = transformer.stream_transform(text)
        chunks = []
        try:
            while True:
                try:
                    chunk = next(gen)
                except StopIteration as stop:
                    token_brake.record(stop.value or 0)
                    if email_me:
                        line = send_result("".join(chunks))
                        yield f"data: {json.dumps(line)}\n\n"
                    yield "event: done\ndata: end\n\n"
                    return
                chunks.append(chunk)
                yield f"data: {json.dumps(chunk)}\n\n"
        except Exception:  # noqa: BLE001
            # Tokens generated before a mid-stream failure are not recorded.
            current_app.logger.exception("transform stream failed")
            yield 'event: error\ndata: "Something went wrong. Please try again."\n\n'

    return Response(
        stream_with_context(event_stream()), mimetype="text/event-stream"
    )
