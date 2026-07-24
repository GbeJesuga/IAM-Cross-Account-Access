terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Security/Management account — this is where your AWS CLI credentials
# already point (the account you ran `aws configure` against).
provider "aws" {
  alias  = "security"
  region = var.region
}

# Workload account — Terraform reaches this one by assuming the
# OrganizationAccountAccessRole, which AWS automatically creates in every
# member account when you add it via AWS Organizations. No separate
# credentials needed for this account.
provider "aws" {
  alias  = "workload"
  region = var.region

  assume_role {
    role_arn = "arn:aws:iam::${var.workload_account_id}:role/OrganizationAccountAccessRole"
  }
}
