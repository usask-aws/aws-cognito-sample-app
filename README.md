# Sarcastifyer

This app is a PROOF OF CONCEPT only, meant to highlight AWS Cognito use
for user authentication and authorization.

Stateless Flask app that rewrites text to be sarcastic via the Anthropic API,
deployed as a single ECS Fargate task behind an HTTPS ALB (ACM certificate, REGIONAL
WAF, all in `ca-central-1`) at `https://sarcastifyer.example.com`. Users sign in
with an emailed one-time code and admins with a password and optional MFA, through two
Amazon Cognito user pools. SES sends result emails and forwards inbound mail for the
domain. See [docs/DESIGN.md](docs/DESIGN.md) for the design and architecture.

## Local development - how to run Python tests

MacOS / Linux
```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest -v
```

Windows
```bash
python -m venv .venv && . .venv/Scripts/activate
pip install -r requirements-dev.txt
pytest -v
```

The tests need no AWS access. Running the app itself does: at startup it reads the Flask signing
key and both Cognito client secrets from Secrets Manager. Only a missing Anthropic API key is
tolerated. To run it locally without AWS, use the smoke test below.

### Local development - Running the app in Docker

Boots the real image with stub secrets and Cognito settings. It makes no AWS or Anthropic calls.

1. Save this as `stub_wsgi.py` **outside the repository**:
   ```python
   """Local test only: boot the real app with stub secrets and Cognito settings."""
   from app import config, create_app
   from app.secrets import SecretNotFoundError


   def _secrets(name):
       if name == config.SECRET_ANTHROPIC_API_KEY:
           raise SecretNotFoundError(name)  # MissingKeyTransformer: no Anthropic calls
       return {
           config.SECRET_FLASK_SIGNING_KEY: "smoke-signing-key",
           config.SECRET_COGNITO_USERS_CLIENT: "smoke-users-secret",
           config.SECRET_COGNITO_ADMINS_CLIENT: "smoke-admins-secret",
       }[name]


   app = create_app(secret_provider=_secrets)
   ```
2. From the repository root, set `STUB` to that file's path, then build, run and check. The stub
   is copied in with `docker cp` because a bind mount may not reach a Docker daemon running in
   another VM.
   ```bash
   STUB=/path/to/stub_wsgi.py
   docker build --platform linux/amd64 -t sarcastifyer-smoke:local .
   docker create --name sarcastifyer-smoke -p 18080:8080 \
     -e COGNITO_USERS_POOL_ID=ca-central-1_Users1 -e COGNITO_USERS_CLIENT_ID=users-client \
     -e COGNITO_USERS_DOMAIN=sarcastifyer-users.auth.ca-central-1.amazoncognito.com \
     -e COGNITO_ADMINS_POOL_ID=ca-central-1_Admins1 -e COGNITO_ADMINS_CLIENT_ID=admins-client \
     -e COGNITO_ADMINS_DOMAIN=sarcastifyer-admins.auth.ca-central-1.amazoncognito.com \
     sarcastifyer-smoke:local gunicorn --bind 0.0.0.0:8080 --workers 1 --threads 8 app.stub_wsgi:app
   docker cp "$STUB" sarcastifyer-smoke:/srv/app/stub_wsgi.py
   docker start sarcastifyer-smoke && sleep 5

   curl -s -w ' %{http_code}\n' localhost:18080/healthz              # {"status":"ok"} 200
   curl -s localhost:18080/ | grep -o 'href="/auth/login"'             # landing page
   curl -s localhost:18080/admin | grep -o 'href="/admin/auth/login"'  # admin sign-in page
   curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' localhost:18080/auth/login
   #   302 https://sarcastifyer-users.auth.ca-central-1.amazoncognito.com/oauth2/authorize?...code_challenge_method=S256
   curl -s -o /dev/null -w '%{http_code}\n' localhost:18080/login    # 404

   docker rm -f sarcastifyer-smoke && docker rmi sarcastifyer-smoke:local
   ```
   On Apple Silicon, Docker warns that the image's platform (amd64) doesn't match the host. That's
   expected: the image is built for the Fargate task and runs under emulation.

## Deployment and operations

All deployment steps live in the [operations runbook](docs/RUNBOOK.md): first-time
setup (state bucket, initial deploy), deploying a new image, and day-to-day operations.

## AI assistance

This application was designed and implemented with AI assistance. Guidance for AI agents working
on the code is in [AGENTS.md](AGENTS.md).
