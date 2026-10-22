# Domain identity with Easy DKIM. SES signs mail From any address on the domain once
# the three DKIM CNAMEs are published in the org zone (permanent: signing stops if removed).
resource "aws_sesv2_email_identity" "domain" {
  email_identity = var.domain_name

  dkim_signing_attributes {
    next_signing_key_length = "RSA_2048_BIT"
  }
}

# Custom MAIL FROM (envelope sender) on a subdomain, so SPF aligns with the From domain
# too. Needs the MX + TXT in output mail_from_records; until they resolve, SES falls
# back to its own amazonses.com MAIL FROM rather than rejecting sends.
resource "aws_sesv2_email_identity_mail_from_attributes" "domain" {
  email_identity         = aws_sesv2_email_identity.domain.email_identity
  mail_from_domain       = "mail.${var.domain_name}"
  behavior_on_mx_failure = "USE_DEFAULT_VALUE"
}

# Bounces and complaints for mail sent From the domain go to SNS (see alerts.tf).
# With SNS in place, email feedback forwarding is off: otherwise SES mails bounces to
# hello@, which the inbound forwarder would forward again.
resource "aws_ses_identity_notification_topic" "domain" {
  for_each                 = toset(["Bounce", "Complaint"])
  identity                 = aws_sesv2_email_identity.domain.email_identity
  notification_type        = each.value
  topic_arn                = aws_sns_topic.alerts.arn
  include_original_headers = true
}

resource "aws_sesv2_email_identity_feedback_attributes" "domain" {
  email_identity           = aws_sesv2_email_identity.domain.email_identity
  email_forwarding_enabled = false
  depends_on               = [aws_ses_identity_notification_topic.domain]
}

# The app sends From var.email_sender, an address on the domain identity, and only
# to the signed-in user's own email. Those addresses can't be listed in IAM, so the
# policy pins the From address only (accepted risk, see docs/DESIGN.md §12).
data "aws_iam_policy_document" "send_email" {
  statement {
    actions   = ["ses:SendEmail"]
    resources = [aws_sesv2_email_identity.domain.arn]
    condition {
      test     = "StringEquals"
      variable = "ses:FromAddress"
      values   = [var.email_sender]
    }
  }
}

resource "aws_iam_role_policy" "ecs_task_send_email" {
  name   = "${var.app_name}-ecs-send-email"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.send_email.json
}
