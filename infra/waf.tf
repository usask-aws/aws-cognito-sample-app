# For a future allowlist: no rule references it while the app is open to all IPs.
# To add one, set default_action to block {} and add an allow rule with an
# ip_set_reference_statement to this set.
resource "aws_wafv2_ip_set" "allow" {
  name               = "${var.app_name}-allow"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.allowed_cidrs
}

# Open to all IPs (default allow), filtered by a sign-in rate limit and the managed
# rule groups in var.waf_managed_rule_groups.
resource "aws_wafv2_web_acl" "app" {
  name  = "${var.app_name}-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Sign-in brake: block an IP for the rest of the window once it sends more than
  # 100 requests in 5 minutes to the app's sign-in routes (/auth/* and
  # /admin/auth/*, any method). Password and code entry happen on Cognito's
  # managed login, outside this WAF.
  rule {
    name     = "rate-limit-login"
    priority = 0
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit                 = 100
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"
        scope_down_statement {
          or_statement {
            dynamic "statement" {
              for_each = ["/auth/", "/admin/auth/"]
              content {
                byte_match_statement {
                  search_string         = statement.value
                  positional_constraint = "STARTS_WITH"
                  field_to_match {
                    uri_path {}
                  }
                  # Decode and normalize as gunicorn/Flask do, so variants such as
                  # //auth/login and /%61uth/login are counted too.
                  text_transformation {
                    priority = 0
                    type     = "URL_DECODE"
                  }
                  text_transformation {
                    priority = 1
                    type     = "NORMALIZE_PATH"
                  }
                }
              }
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.app_name}-rate-limit-login"
      sampled_requests_enabled   = true
    }
  }

  # One rule per AWS managed rule group, in list order, at its default actions.
  dynamic "rule" {
    for_each = var.waf_managed_rule_groups
    content {
      name     = rule.value
      priority = rule.key + 1
      override_action {
        none {}
      }
      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = rule.value
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.app_name}-${rule.value}"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.app_name}-acl"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "app" {
  resource_arn = aws_lb.app.arn
  web_acl_arn  = aws_wafv2_web_acl.app.arn
}
