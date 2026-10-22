resource "aws_ecs_cluster" "app" {
  name = var.app_name
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${var.app_name}"
  retention_in_days = 30
}

# Resolve the deployed tag to its digest. The task def pins the digest, so the
# image can't change under it, and re-applying the same tag changes nothing.
# Named by var.app_name, not the repo resource, so a change to the repo doesn't
# defer this read to apply time and force a new task def.
data "aws_ecr_image" "app" {
  repository_name = var.app_name
  image_tag       = var.image_tag
}

resource "aws_ecs_task_definition" "app" {
  family                   = var.app_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  # Pin the platform explicitly. The image must be built for this architecture
  # (docker build --platform linux/amd64); an arm64 image starts then exits with
  # no logs on an X86_64 host.
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name         = var.app_name
      image        = "${aws_ecr_repository.app.repository_url}@${data.aws_ecr_image.app.image_digest}"
      essential    = true
      portMappings = [{ containerPort = 8080, protocol = "tcp" }]
      environment = [
        { name = "AWS_REGION", value = var.region },
        { name = "SECRET_ANTHROPIC_API_KEY", value = aws_secretsmanager_secret.anthropic_api_key.name },
        { name = "SECRET_FLASK_SIGNING_KEY", value = aws_secretsmanager_secret.flask_signing_key.name },
        { name = "EMAIL_SENDER", value = var.email_sender },
        { name = "EMAIL_SENDER_NAME", value = var.email_sender_name },
        { name = "APP_BASE_URL", value = local.app_base_url },
        { name = "COGNITO_USERS_POOL_ID", value = aws_cognito_user_pool.users.id },
        { name = "COGNITO_USERS_CLIENT_ID", value = aws_cognito_user_pool_client.users.id },
        { name = "COGNITO_USERS_DOMAIN", value = "${aws_cognito_user_pool_domain.users.domain}.auth.${var.region}.amazoncognito.com" },
        { name = "SECRET_COGNITO_USERS_CLIENT", value = aws_secretsmanager_secret.cognito_users_client.name },
        { name = "COGNITO_ADMINS_POOL_ID", value = aws_cognito_user_pool.admins.id },
        { name = "COGNITO_ADMINS_CLIENT_ID", value = aws_cognito_user_pool_client.admins.id },
        { name = "COGNITO_ADMINS_DOMAIN", value = "${aws_cognito_user_pool_domain.admins.domain}.auth.${var.region}.amazoncognito.com" },
        { name = "SECRET_COGNITO_ADMINS_CLIENT", value = aws_secretsmanager_secret.cognito_admins_client.name },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "app"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "app" {
  name            = var.app_name
  cluster         = aws_ecs_cluster.app.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  # Stop the old task before starting the new one -> never more than one task.
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  network_configuration {
    subnets          = [data.aws_subnet.public_1a.id]
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = var.app_name
    container_port   = 8080
  }

  depends_on = [aws_lb_listener.http]
}
