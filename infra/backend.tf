terraform {
  backend "s3" {
    # S3 native state locking (no DynamoDB table); requires Terraform >= 1.11.
    use_lockfile = true

    # The bucket name is account-specific, so it's kept out of the repository:
    # it comes from the gitignored infra/backend.hcl (copy backend.hcl.example),
    # passed with: terraform init -backend-config=backend.hcl
    key     = "sarcastifyer/terraform.tfstate"
    region  = "ca-central-1"
    encrypt = true
  }
}
