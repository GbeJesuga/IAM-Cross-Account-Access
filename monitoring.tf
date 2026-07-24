# ---------------------------------------------------------------------------
# Monitoring: alert via email whenever SecurityAuditRole is assumed.
#
# NOTE: an earlier version of this file assumed EventBridge would receive
# CloudTrail management events with no Trail resource needed. That's only
# true for the console's 90-day "Event history" view — actual delivery to
# EventBridge requires an active Trail, which is what we create below.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail_logs" {
  provider      = aws.security
  bucket        = "security-audit-cloudtrail-${data.aws_caller_identity.security.account_id}"
  force_destroy = true # convenience for a portfolio project; wouldn't set this in production
}

resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  provider = aws.security
  bucket   = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.security.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "security_trail" {
  provider                      = aws.security
  name                          = "security-account-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = false # single-region keeps this minimal/cheap for a portfolio project
  enable_logging                = true

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs_policy]
}

resource "aws_sns_topic" "assume_role_alerts" {
  provider = aws.security
  name     = "security-audit-role-assumed-alerts"
}

resource "aws_sns_topic_subscription" "email_alert" {
  provider  = aws.security
  topic_arn = aws_sns_topic.assume_role_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "assume_role_rule" {
  provider    = aws.security
  name        = "detect-security-audit-role-assumed"
  description = "Fires whenever SecurityAuditRole is assumed via STS"

  event_pattern = jsonencode({
    source      = ["aws.sts"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["AssumeRole"]
      requestParameters = {
        roleArn = [aws_iam_role.security_audit_role.arn]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "send_to_sns" {
  provider  = aws.security
  rule      = aws_cloudwatch_event_rule.assume_role_rule.name
  target_id = "send-to-sns"
  arn       = aws_sns_topic.assume_role_alerts.arn
}

# EventBridge needs explicit permission to publish to the SNS topic.
resource "aws_sns_topic_policy" "allow_eventbridge_publish" {
  provider = aws.security
  arn      = aws_sns_topic.assume_role_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridgePublish"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.assume_role_alerts.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.assume_role_rule.arn
          }
        }
      }
    ]
  })
}
