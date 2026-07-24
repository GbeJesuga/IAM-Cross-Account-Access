variable "security_account_id" {
  description = "12-digit AWS account ID of the Security/Management account (where auditors live)"
  type        = string
}

variable "workload_account_id" {
  description = "12-digit AWS account ID of the Workload account (the account being audited)"
  type        = string
}

variable "region" {
  description = "AWS region to operate in (IAM is global, but the provider still needs one)"
  type        = string
  default     = "us-east-1"
}

variable "external_id" {
  description = "A shared secret required in the AssumeRole call, to prevent the 'confused deputy' problem"
  type        = string
  default     = "portfolio-project-1-cross-account"
}

variable "alert_email" {
  description = "Email address to receive alerts when SecurityAuditRole is assumed"
  type        = string
}
