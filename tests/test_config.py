from app import config


def test_guardrail_constants_match_spec():
    assert config.MAX_INPUT_CHARS == 5000
    assert config.RATE_LIMIT_MAX_REQUESTS == 2
    assert config.RATE_LIMIT_WINDOW_SECONDS == 60
    assert config.DAILY_OUTPUT_TOKEN_CAP == 50_000
    assert config.SESSION_LIFETIME_SECONDS == 28_800
    assert config.REVALIDATE_SECONDS == 900


def test_model_settings_match_spec():
    assert config.MODEL == "claude-opus-4-8"
    assert config.MAX_OUTPUT_TOKENS == 4096


def test_secret_names_present():
    assert config.SECRET_ANTHROPIC_API_KEY
    assert config.SECRET_FLASK_SIGNING_KEY
    assert config.SECRET_COGNITO_USERS_CLIENT == "sarcastifyer/cognito-users-client"
    assert config.SECRET_COGNITO_ADMINS_CLIENT == "sarcastifyer/cognito-admins-client"


def test_app_base_url_default():
    assert config.APP_BASE_URL == "https://sarcastifyer.example.com"


def test_system_prompt_is_restyle_only():
    p = config.SYSTEM_PROMPT.lower()
    assert "sarcastic" in p
    assert "intent" in p or "meaning" in p
