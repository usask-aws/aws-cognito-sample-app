# Definitions only. Values are set in environment.auto.tfvars (gitignored); copy
# environment.auto.tfvars.example to start one.

variable "region" {
  type = string
}

variable "app_name" {
  type        = string
  description = "Prefix for resource names."
}

variable "allowed_cidrs" {
  type        = list(string)
  description = "Allowlist kept for future use. Feeds the WAF IP set only; no WAF rule or security group uses it while the app is open to all IPs."
}

variable "image_tag" {
  type        = string
  description = "Short git SHA of the image to deploy. Required; no default. The task def pins the tag's digest."
}

variable "email_sender" {
  type        = string
  description = "From address for result emails, Cognito emails and forwarded inbound mail. Must be on domain_name (the verified, DKIM-signed SES domain identity)."
}

variable "email_sender_name" {
  type        = string
  description = "Display name on the From of every email: Cognito's and the app's."
}

variable "inbound_local_parts" {
  type        = list(string)
  description = "Addresses on domain_name that accept mail; SES rejects all others at SMTP time."
}

variable "inbound_prefix" {
  type        = string
  description = "S3 key prefix for stored inbound mail. Must end with \"/\"."

  validation {
    condition     = endswith(var.inbound_prefix, "/")
    error_message = "inbound_prefix must end with \"/\"."
  }
}

variable "forward_to" {
  type        = string
  description = "Where inbound mail and alerts are forwarded."
}

variable "domain_name" {
  type        = string
  description = "Custom domain for the app. Its DNS is in an org-controlled Route 53 zone in another account."
}

variable "cognito_required_attributes" {
  type        = list(string)
  description = "Standard attributes every account must have, in both pools. Can't change after a pool is created."
}

variable "waf_managed_rule_groups" {
  type        = list(string)
  description = "AWS managed rule groups (no subscription fee) in evaluation order. Their WCUs plus the rate rule must fit in the web ACL's capacity."
}
