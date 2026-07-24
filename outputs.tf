output "security_audit_role_arn" {
  description = "The ARN you'll use in `aws sts assume-role` to test the setup"
  value       = aws_iam_role.security_audit_role.arn
}

output "external_id" {
  description = "The External ID you'll need to pass when assuming the role"
  value       = var.external_id
}

output "security_account_user" {
  description = "The IAM user in the Security account that was granted assume-role permission"
  value       = data.aws_iam_user.current_user.user_name
}

output "alert_topic_arn" {
  description = "SNS topic ARN — check your email to confirm the subscription after apply"
  value       = aws_sns_topic.assume_role_alerts.arn
}
