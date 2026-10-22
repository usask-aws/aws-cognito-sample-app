resource "aws_lb" "app" {
  name               = "${var.app_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [data.aws_subnet.public_1a.id, data.aws_subnet.public_1b.id]

  # Drop malformed headers rather than forwarding them (request-smuggling defence).
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "app" {
  name        = "${var.app_name}-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.primary.id
  target_type = "ip"

  health_check {
    path                = "/healthz"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      path        = "/"
      query       = ""
      status_code = "HTTP_301"
    }
  }
}

# TLS ends here; the ALB-to-task hop stays HTTP on 8080.
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.app.certificate_arn

  # HSTS. Raise to max-age=31536000 once HTTPS has run cleanly for a few days.
  # No includeSubDomains/preload: example.com is the org's zone.
  routing_http_response_strict_transport_security_header_value = "max-age=300"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
