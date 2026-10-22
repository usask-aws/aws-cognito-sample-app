# TLS certificate for the ALB's custom domain. DNS for example.com lives in
# an org-controlled Route 53 zone in another account, so Terraform can't create
# the validation record: it's requested through the org DNS workflow from the
# acm_validation_records output. That CNAME must stay in place permanently, or
# ACM's automatic renewal fails and the cert expires.
resource "aws_acm_certificate" "app" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# Waits for the cert to be ISSUED, so the HTTPS listener is never attached to a
# pending cert. No validation_record_fqdns: the record isn't managed here.
resource "aws_acm_certificate_validation" "app" {
  certificate_arn = aws_acm_certificate.app.arn
}
