output "app_url" {
  value = "https://${var.domain_name}"
}

output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}

# The deployed tag. Infra-only applies reuse it: see docs/RUNBOOK.md.
output "image_tag" {
  value = var.image_tag
}

# The CNAME to request through the org DNS workflow to validate the ACM cert.
output "acm_validation_records" {
  value = [for o in aws_acm_certificate.app.domain_validation_options : {
    name  = o.resource_record_name
    type  = o.resource_record_type
    value = o.resource_record_value
  }]
}

# The MX record to request through the org DNS workflow for inbound mail.
output "inbound_mx_record" {
  value = {
    name  = "${var.domain_name}."
    type  = "MX"
    value = "10 inbound-smtp.${var.region}.amazonaws.com."
  }
}

# MAIL FROM records to request through the org DNS workflow (SPF alignment).
output "mail_from_records" {
  value = [
    {
      name  = "${aws_sesv2_email_identity_mail_from_attributes.domain.mail_from_domain}."
      type  = "MX"
      value = "10 feedback-smtp.${var.region}.amazonses.com."
    },
    {
      name  = "${aws_sesv2_email_identity_mail_from_attributes.domain.mail_from_domain}."
      type  = "TXT"
      value = "\"v=spf1 include:amazonses.com ~all\""
    },
  ]
}

# DMARC policy record to request through the org DNS workflow. No rua: reports not wanted.
output "dmarc_record" {
  value = {
    name  = "_dmarc.${var.domain_name}."
    type  = "TXT"
    value = "\"v=DMARC1; p=quarantine\""
  }
}

# The three DKIM CNAMEs to request through the org DNS workflow.
# dkim.amazonses.com is the SES DKIM domain for ca-central-1 (AWS General Reference).
output "dkim_records" {
  value = [for t in aws_sesv2_email_identity.domain.dkim_signing_attributes[0].tokens : {
    name  = "${t}._domainkey.${var.domain_name}."
    type  = "CNAME"
    value = "${t}.dkim.amazonses.com."
  }]
}

# Cognito pool and client IDs, for the runbook's admin CLI commands.
output "cognito_admins_pool_id" {
  value = aws_cognito_user_pool.admins.id
}

output "cognito_users_pool_id" {
  value = aws_cognito_user_pool.users.id
}

output "cognito_admins_client_id" {
  value = aws_cognito_user_pool_client.admins.id
}

output "cognito_users_client_id" {
  value = aws_cognito_user_pool_client.users.id
}

output "sign_in_urls" {
  value = {
    users  = "${local.app_base_url}/"
    admins = "${local.app_base_url}/admin"
  }
}
