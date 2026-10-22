# One SNS topic for operator alerts, emailed to var.forward_to: SES bounces and
# complaints for the domain identity, and forwarder Lambda errors. The email
# subscription must be confirmed from the link SNS sends after the first apply.

resource "aws_sns_topic" "alerts" {
  name = "${var.app_name}-alerts"
}

# Only SES (for the domain identity) and CloudWatch (for this stack's alarm) may publish.
data "aws_iam_policy_document" "alerts" {
  statement {
    sid       = "AllowSesNotifications"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["ses.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:ses:${var.region}:${data.aws_caller_identity.current.account_id}:identity/${var.domain_name}"]
    }
  }
  statement {
    sid       = "AllowCloudWatchAlarms"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudwatch:${var.region}:${data.aws_caller_identity.current.account_id}:alarm:${var.app_name}-*"]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts.json
}

resource "aws_sns_topic_subscription" "alerts_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.forward_to
}

# Any failed forwarder invocation. Async invokes retry twice, so one bad message can
# alarm more than once; the message stays in S3 for 7 days to re-forward by hand.
resource "aws_cloudwatch_metric_alarm" "forwarder_errors" {
  alarm_name          = "${var.app_name}-inbound-forwarder-errors"
  alarm_description   = "Inbound mail forwarder Lambda failed; see /aws/lambda/${var.app_name}-inbound-forwarder."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.forwarder.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}
