variable "region" {
  type    = string
  default = "ca-central-1"
}

variable "state_bucket_name" {
  type        = string
  description = "Globally-unique S3 bucket name for Terraform state."
}
