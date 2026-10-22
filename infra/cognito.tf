# Two Cognito user pools (Essentials plan) with managed login on prefix domains.
# - admins: password, then optional TOTP or email MFA. Accounts are created with
#   the AWS CLI only (docs/RUNBOOK.md).
# - users: one-time code sent by email; no password, no MFA. Admins invite them
#   from /admin.
# No self-signup, no federation, no SMS. Email goes through the SES domain identity
# (DEVELOPER mode, via the Cognito email service-linked role).
#
# Required attributes can't change after a pool is created, and deletion
# protection must be turned off before a pool can be destroyed. Destroying a
# pool deletes every account in it.

locals {
  app_base_url = "https://${var.domain_name}"
  cognito_from = "${var.email_sender_name} <${var.email_sender}>"
}

resource "aws_cognito_user_pool" "admins" {
  name                     = "${var.app_name}-admins"
  user_pool_tier           = "ESSENTIALS"
  deletion_protection      = "ACTIVE"
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]
  mfa_configuration        = "OPTIONAL"

  username_configuration {
    case_sensitive = false
  }

  sign_in_policy {
    allowed_first_auth_factors = ["PASSWORD"]
  }

  software_token_mfa_configuration {
    enabled = true
  }

  # Template for MFA codes sent by email. Email MFA needs DEVELOPER email sending.
  email_mfa_configuration {
    subject = "Your Sarcastifyer sign-in code"
    message = "<p>Your Sarcastifyer admin sign-in code is {####}.</p><p>If you didn't just try to sign in, change your password from the Account page.</p>"
  }

  # No self-service recovery: managed login shows no "Forgot password" link. A
  # locked-out admin is recovered with the CLI (docs/RUNBOOK.md).
  account_recovery_setting {
    recovery_mechanism {
      name     = "admin_only"
      priority = 1
    }
  }

  password_policy {
    minimum_length                   = 8
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    password_history_size            = 0
    temporary_password_validity_days = 7
  }

  email_configuration {
    email_sending_account = "DEVELOPER"
    source_arn            = aws_sesv2_email_identity.domain.arn
    from_email_address    = local.cognito_from
  }

  admin_create_user_config {
    allow_admin_create_user_only = true

    invite_message_template {
      email_subject = "Your Sarcastifyer admin account"
      email_message = "<p>An administrator account has been created for you on Sarcastifyer.</p><p>Username: {username}<br>Temporary password: {####}</p><p>Sign in at ${local.app_base_url}/admin within 7 days and choose a new password.</p>"
      # Never sent (no SMS configuration), but Cognito rejects an empty SMS template.
      sms_message = "Your Sarcastifyer username is {username} and code is {####}."
    }
  }

  dynamic "schema" {
    for_each = var.cognito_required_attributes
    content {
      name                = schema.value
      attribute_data_type = "String"
      required            = true
      mutable             = true
      string_attribute_constraints {
        min_length = 0
        max_length = 2048
      }
    }
  }
}

resource "aws_cognito_user_pool" "users" {
  name                     = "${var.app_name}-users"
  user_pool_tier           = "ESSENTIALS"
  deletion_protection      = "ACTIVE"
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]
  # Cognito can't combine a one-time-code first factor with MFA.
  mfa_configuration = "OFF"

  username_configuration {
    case_sensitive = false
  }

  # Sign-in code emails use Cognito's default wording: with MFA off, the provider
  # doesn't apply an email_mfa_configuration template.
  # Cognito requires PASSWORD among the first factors; users have no password,
  # so they still sign in with email codes.
  sign_in_policy {
    allowed_first_auth_factors = ["PASSWORD", "EMAIL_OTP"]
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "admin_only"
      priority = 1
    }
  }

  # Applies to no one: user-pool accounts have no password. Set explicitly anyway.
  password_policy {
    minimum_length                   = 8
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    password_history_size            = 0
    temporary_password_validity_days = 7
  }

  email_configuration {
    email_sending_account = "DEVELOPER"
    source_arn            = aws_sesv2_email_identity.domain.arn
    from_email_address    = local.cognito_from
  }

  admin_create_user_config {
    allow_admin_create_user_only = true

    # Users are created without a password, so Cognito has no temporary password
    # to put in {####}. The provider insists on the placeholder, so it sits in an
    # HTML comment where it isn't shown.
    invite_message_template {
      email_subject = "You're invited to Sarcastifyer"
      email_message = "<p>You've been invited to use Sarcastifyer.</p><p>Sign in at ${local.app_base_url}/ with this email address ({username}). Each time you sign in, we'll email you a one-time code. There's no password.</p><!-- {####} -->"
      # Never sent (no SMS configuration), but Cognito rejects an empty SMS template.
      sms_message = "Your Sarcastifyer username is {username} and code is {####}."
    }
  }

  dynamic "schema" {
    for_each = var.cognito_required_attributes
    content {
      name                = schema.value
      attribute_data_type = "String"
      required            = true
      mutable             = true
      string_attribute_constraints {
        min_length = 0
        max_length = 2048
      }
    }
  }
}

# Prefix domains on auth.<region>.amazoncognito.com: no DNS records, no us-east-1
# certificate. The names must be unique in the region across all AWS accounts.
resource "aws_cognito_user_pool_domain" "admins" {
  domain                = "${var.app_name}-admins"
  user_pool_id          = aws_cognito_user_pool.admins.id
  managed_login_version = 2
}

resource "aws_cognito_user_pool_domain" "users" {
  domain                = "${var.app_name}-users"
  user_pool_id          = aws_cognito_user_pool.users.id
  managed_login_version = 2
}

# Confidential clients (client secret), authorization code flow with PKCE.
# Tokens last 60 minutes; the refresh token is set to its 60-minute minimum and
# the app never stores it.
resource "aws_cognito_user_pool_client" "admins" {
  name                                 = "${var.app_name}-admins-web"
  user_pool_id                         = aws_cognito_user_pool.admins.id
  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile", "aws.cognito.signin.user.admin"]
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = ["${local.app_base_url}/admin/auth/callback"]
  logout_urls                          = ["${local.app_base_url}/admin"]
  explicit_auth_flows                  = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors        = "ENABLED"
  enable_token_revocation              = true
  read_attributes                      = ["email", "email_verified", "given_name", "family_name"]
  id_token_validity                    = 60
  access_token_validity                = 60
  refresh_token_validity               = 60

  token_validity_units {
    id_token      = "minutes"
    access_token  = "minutes"
    refresh_token = "minutes"
  }
}

resource "aws_cognito_user_pool_client" "users" {
  name                                 = "${var.app_name}-users-web"
  user_pool_id                         = aws_cognito_user_pool.users.id
  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = ["${local.app_base_url}/auth/callback"]
  logout_urls                          = ["${local.app_base_url}/"]
  # ALLOW_USER_AUTH is choice-based sign-in; managed login uses it for email codes.
  explicit_auth_flows           = ["ALLOW_USER_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors = "ENABLED"
  enable_token_revocation       = true
  read_attributes               = ["email", "email_verified", "given_name", "family_name"]
  id_token_validity             = 60
  access_token_validity         = 60
  refresh_token_validity        = 60

  token_validity_units {
    id_token      = "minutes"
    access_token  = "minutes"
    refresh_token = "minutes"
  }
}

# Managed login needs a branding style for clients created through the API.
resource "aws_cognito_managed_login_branding" "admins" {
  user_pool_id                = aws_cognito_user_pool.admins.id
  client_id                   = aws_cognito_user_pool_client.admins.id
  use_cognito_provided_values = true
}

resource "aws_cognito_managed_login_branding" "users" {
  user_pool_id                = aws_cognito_user_pool.users.id
  client_id                   = aws_cognito_user_pool_client.users.id
  use_cognito_provided_values = true
}

# Client secrets for the app. Accepted risk: the values are in Terraform state,
# like the Flask signing key (state bucket encryption and access controls).
resource "aws_secretsmanager_secret" "cognito_admins_client" {
  name = "${var.app_name}/cognito-admins-client"
}

resource "aws_secretsmanager_secret_version" "cognito_admins_client" {
  secret_id     = aws_secretsmanager_secret.cognito_admins_client.id
  secret_string = aws_cognito_user_pool_client.admins.client_secret
}

resource "aws_secretsmanager_secret" "cognito_users_client" {
  name = "${var.app_name}/cognito-users-client"
}

resource "aws_secretsmanager_secret_version" "cognito_users_client" {
  secret_id     = aws_secretsmanager_secret.cognito_users_client.id
  secret_string = aws_cognito_user_pool_client.users.client_secret
}
