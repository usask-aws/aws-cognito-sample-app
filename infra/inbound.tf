# Inbound mail for var.domain_name: SES accepts only the inbound_local_parts
# addresses, stores each message in S3, and a Lambda forwards it to var.forward_to.
# Needs the MX record in output inbound_mx_record published in the org zone.

locals {
  inbound_rule_set  = "${var.app_name}-inbound"
  inbound_rule_name = "${var.app_name}-forward"
  # Built from names (not the resource) so the bucket policy and Lambda permission
  # can exist before the rule, which SES checks when the rule is created.
  inbound_rule_arn = "arn:aws:ses:${var.region}:${data.aws_caller_identity.current.account_id}:receipt-rule-set/${local.inbound_rule_set}:receipt-rule/${local.inbound_rule_name}"
}

# --- Mail store ---

resource "aws_s3_bucket" "inbound" {
  bucket = "${var.app_name}-inbound-mail-${data.aws_caller_identity.current.account_id}-${var.region}"
}

resource "aws_s3_bucket_ownership_controls" "inbound" {
  bucket = aws_s3_bucket.inbound.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "inbound" {
  bucket                  = aws_s3_bucket.inbound.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "inbound" {
  bucket = aws_s3_bucket.inbound.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Inbound mail is arbitrary third-party content: keep it only long enough to
# re-forward by hand if the Lambda fails.
resource "aws_s3_bucket_lifecycle_configuration" "inbound" {
  bucket = aws_s3_bucket.inbound.id
  rule {
    id     = "expire-inbound-mail"
    status = "Enabled"
    filter {}
    expiration {
      days = 7
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

data "aws_iam_policy_document" "inbound_bucket" {
  statement {
    sid       = "AllowSesReceiptRulePut"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.inbound.arn}/${var.inbound_prefix}*"]
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
      values   = [local.inbound_rule_arn]
    }
  }
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.inbound.arn, "${aws_s3_bucket.inbound.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "inbound" {
  bucket = aws_s3_bucket.inbound.id
  policy = data.aws_iam_policy_document.inbound_bucket.json
  # Policy before the public access block settles can fail with AccessDenied.
  depends_on = [aws_s3_bucket_public_access_block.inbound]
}

# --- Forwarder Lambda ---

data "archive_file" "forwarder" {
  type        = "zip"
  source_dir  = "${path.module}/../forwarder"
  output_path = "${path.module}/.build/forwarder.zip"
  excludes    = ["__pycache__"]
  # Fixed file modes, so the zip (and source_code_hash) is the same on every
  # machine. Line endings are fixed by .gitattributes.
  output_file_mode = "0644"
}

resource "aws_cloudwatch_log_group" "forwarder" {
  name              = "/aws/lambda/${var.app_name}-inbound-forwarder"
  retention_in_days = 30
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "forwarder" {
  name               = "${var.app_name}-inbound-forwarder"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Logs, read the stored message, and re-send it only From email_sender to forward_to.
data "aws_iam_policy_document" "forwarder" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.forwarder.arn}:*"]
  }
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.inbound.arn}/${var.inbound_prefix}*"]
  }
  # SES v2 SendEmail with Raw content; both sending actions are listed because the
  # SES docs don't pin which one a v2 raw send is authorized against.
  statement {
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = [aws_sesv2_email_identity.domain.arn]
    condition {
      test     = "StringEquals"
      variable = "ses:FromAddress"
      values   = [var.email_sender]
    }
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "ses:Recipients"
      values   = [var.forward_to]
    }
  }
}

resource "aws_iam_role_policy" "forwarder" {
  name   = "${var.app_name}-inbound-forwarder"
  role   = aws_iam_role.forwarder.id
  policy = data.aws_iam_policy_document.forwarder.json
}

resource "aws_lambda_function" "forwarder" {
  function_name    = "${var.app_name}-inbound-forwarder"
  role             = aws_iam_role.forwarder.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "handler.handler"
  filename         = data.archive_file.forwarder.output_path
  source_code_hash = data.archive_file.forwarder.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      INBOUND_BUCKET = aws_s3_bucket.inbound.id
      INBOUND_PREFIX = var.inbound_prefix
      FORWARD_FROM   = var.email_sender
      FORWARD_TO     = var.forward_to
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.forwarder.name
  }

  depends_on = [aws_iam_role_policy.forwarder]
}

resource "aws_lambda_permission" "ses" {
  statement_id   = "AllowSesReceiptRule"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.forwarder.function_name
  principal      = "ses.amazonaws.com"
  source_account = data.aws_caller_identity.current.account_id
  source_arn     = local.inbound_rule_arn
}

# --- Receipt rules ---

# Only one rule set can be active per account and Region (none existed before this).
resource "aws_ses_receipt_rule_set" "inbound" {
  rule_set_name = local.inbound_rule_set
}

resource "aws_ses_active_receipt_rule_set" "inbound" {
  rule_set_name = aws_ses_receipt_rule_set.inbound.rule_set_name
}

resource "aws_ses_receipt_rule" "forward" {
  name          = local.inbound_rule_name
  rule_set_name = aws_ses_receipt_rule_set.inbound.rule_set_name
  recipients    = [for p in var.inbound_local_parts : "${p}@${var.domain_name}"]
  enabled       = true
  scan_enabled  = true
  tls_policy    = "Optional"

  s3_action {
    bucket_name       = aws_s3_bucket.inbound.id
    object_key_prefix = var.inbound_prefix
    position          = 1
  }

  lambda_action {
    function_arn    = aws_lambda_function.forwarder.arn
    invocation_type = "Event"
    position        = 2
  }

  depends_on = [aws_s3_bucket_policy.inbound, aws_lambda_permission.ses]
}
