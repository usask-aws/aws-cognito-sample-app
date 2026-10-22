import time
from datetime import timedelta

from flask import Flask, g, render_template, request, session

from app import config, session_auth
from app.account_client import AccountClient
from app.account_web import account
from app.admin_web import admin
from app.audit import AuditLog
from app.auth_web import auth
from app.directory import Directory
from app.guardrails import DailyTokenBrake, RateLimiter
from app.mailer import SesMailer
from app.oidc import OidcClient, PoolConfig, UrllibHttp
from app.secrets import SecretNotFoundError, get_secret
from app.transformer import MissingKeyTransformer, Transformer
from app.web import main

# Endpoints that skip loading the signed-in identity (no Cognito call).
_NO_IDENTITY_ENDPOINTS = (None, "static", "main.healthz")


def build_pools(secret_provider) -> dict[str, PoolConfig]:
    base = config.APP_BASE_URL.rstrip("/")
    return {
        session_auth.USER: PoolConfig(
            name=session_auth.USER,
            region=config.AWS_REGION,
            pool_id=config.COGNITO_USERS_POOL_ID,
            client_id=config.COGNITO_USERS_CLIENT_ID,
            client_secret=secret_provider(config.SECRET_COGNITO_USERS_CLIENT),
            domain=config.COGNITO_USERS_DOMAIN,
            redirect_uri=f"{base}/auth/callback",
            logout_uri=f"{base}/",
            scopes=("openid", "email", "profile"),
        ),
        session_auth.ADMIN: PoolConfig(
            name=session_auth.ADMIN,
            region=config.AWS_REGION,
            pool_id=config.COGNITO_ADMINS_POOL_ID,
            client_id=config.COGNITO_ADMINS_CLIENT_ID,
            client_secret=secret_provider(config.SECRET_COGNITO_ADMINS_CLIENT),
            domain=config.COGNITO_ADMINS_DOMAIN,
            redirect_uri=f"{base}/admin/auth/callback",
            logout_uri=f"{base}/admin",
            scopes=("openid", "email", "profile", "aws.cognito.signin.user.admin"),
        ),
    }


def create_app(
    *,
    secret_provider=get_secret,
    transformer=None,
    mailer=None,
    rate_limiter=None,
    token_brake=None,
    pools=None,
    oidc_client=None,
    directory=None,
    account_client=None,
    audit_log=None,
    clock=time.time,
) -> Flask:
    app = Flask(__name__)
    app.secret_key = secret_provider(config.SECRET_FLASK_SIGNING_KEY)
    app.permanent_session_lifetime = timedelta(seconds=config.SESSION_LIFETIME_SECONDS)
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    if transformer is None:
        try:
            api_key = secret_provider(config.SECRET_ANTHROPIC_API_KEY)
        except SecretNotFoundError:
            # Boot without the key; every transform returns a fixed message.
            transformer = MissingKeyTransformer(config.MISSING_API_KEY_MESSAGE)
        else:
            import anthropic

            client = anthropic.Anthropic(api_key=api_key)
            transformer = Transformer(client, config.MODEL, config.MAX_OUTPUT_TOKENS)

    if mailer is None:
        import boto3

        mailer = SesMailer(
            boto3.client("sesv2", region_name=config.AWS_REGION),
            config.EMAIL_SENDER,
            config.EMAIL_SENDER_NAME,
        )

    if directory is None or account_client is None:
        import boto3

        cognito = boto3.client("cognito-idp", region_name=config.AWS_REGION)
        directory = directory or Directory(
            cognito, config.COGNITO_USERS_POOL_ID, config.COGNITO_ADMINS_POOL_ID
        )
        account_client = account_client or AccountClient(cognito)

    app.extensions["transformer"] = transformer
    app.extensions["mailer"] = mailer
    app.extensions["rate_limiter"] = rate_limiter or RateLimiter(
        config.RATE_LIMIT_MAX_REQUESTS, config.RATE_LIMIT_WINDOW_SECONDS
    )
    app.extensions["token_brake"] = token_brake or DailyTokenBrake(
        config.DAILY_OUTPUT_TOKEN_CAP
    )
    app.extensions["pools"] = pools or build_pools(secret_provider)
    app.extensions["oidc"] = oidc_client or OidcClient(
        UrllibHttp(), clock=clock, leeway=config.TOKEN_LEEWAY_SECONDS
    )
    app.extensions["directory"] = directory
    app.extensions["account_client"] = account_client
    app.extensions["audit"] = audit_log or AuditLog(clock=clock)
    app.extensions["clock"] = clock

    @app.before_request
    def load_identity():
        g.identity = None
        if request.endpoint in _NO_IDENTITY_ENDPOINTS:
            return
        now = clock()
        identity = session_auth.load_identity(session, now, config.SESSION_LIFETIME_SECONDS)
        if identity and session_auth.needs_revalidation(session, now, config.REVALIDATE_SECONDS):
            identity = session_auth.revalidate(session, identity, now, directory, app.logger)
        g.identity = identity

    @app.after_request
    def security_headers(response):
        # No full CSP yet; this only stops framing and MIME sniffing.
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        return response

    @app.context_processor
    def template_globals():
        return {
            "identity": g.get("identity"),
            "csrf_token": lambda: session_auth.csrf_token(session),
        }

    @app.errorhandler(400)
    def bad_request(_error):
        return (
            render_template(
                "error.html",
                title="Request not accepted",
                message="The form expired or was incomplete. Go back, reload the page and try again.",
            ),
            400,
        )

    @app.errorhandler(403)
    def forbidden(_error):
        return (
            render_template(
                "error.html", title="Not allowed", message="You don't have access to this page."
            ),
            403,
        )

    app.register_blueprint(main)
    app.register_blueprint(auth)
    app.register_blueprint(admin)
    app.register_blueprint(account)
    return app
