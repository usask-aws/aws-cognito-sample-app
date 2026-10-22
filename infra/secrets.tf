resource "random_password" "flask_signing_key" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "anthropic_api_key" {
  name = "${var.app_name}/anthropic-api-key"
}

resource "aws_secretsmanager_secret" "flask_signing_key" {
  name = "${var.app_name}/flask-signing-key"
}

resource "aws_secretsmanager_secret_version" "flask_signing_key" {
  secret_id     = aws_secretsmanager_secret.flask_signing_key.id
  secret_string = random_password.flask_signing_key.result
}
