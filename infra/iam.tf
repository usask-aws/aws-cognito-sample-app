data "aws_iam_policy_document" "read_secrets" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.anthropic_api_key.arn,
      aws_secretsmanager_secret.flask_signing_key.arn,
      aws_secretsmanager_secret.cognito_users_client.arn,
      aws_secretsmanager_secret.cognito_admins_client.arn,
    ]
  }
}

# --- ECS roles ---

data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# Execution role: pull image from ECR, write logs to CloudWatch.
resource "aws_iam_role" "ecs_execution" {
  name               = "${var.app_name}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Task role: the app reads its secrets, manages the user pool and re-checks
# signed-in accounts.
resource "aws_iam_role" "ecs_task" {
  name               = "${var.app_name}-ecs-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy" "ecs_task_read_secrets" {
  name   = "${var.app_name}-ecs-read-secrets"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.read_secrets.json
}

# /admin manages the user pool. Session revalidation reads users in both pools.
# Admins are managed with the AWS CLI only, so the admin pool gets AdminGetUser
# and nothing else.
data "aws_iam_policy_document" "cognito" {
  statement {
    sid = "ManageUserPool"
    actions = [
      "cognito-idp:AdminCreateUser",
      "cognito-idp:ListUsers",
      "cognito-idp:AdminGetUser",
      "cognito-idp:AdminDisableUser",
      "cognito-idp:AdminEnableUser",
      "cognito-idp:AdminDeleteUser",
      "cognito-idp:AdminUpdateUserAttributes",
    ]
    resources = [aws_cognito_user_pool.users.arn]
  }
  statement {
    sid       = "RevalidateAdmins"
    actions   = ["cognito-idp:AdminGetUser"]
    resources = [aws_cognito_user_pool.admins.arn]
  }
}

resource "aws_iam_role_policy" "ecs_task_cognito" {
  name   = "${var.app_name}-ecs-cognito"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.cognito.json
}
