# ---------------------------------------------------------------------------
# 1. THE ROLE — lives in the WORKLOAD account.
#    Its trust policy says "only the Security account is allowed to assume me,
#    and only if they present the correct external ID".
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "trust_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.security_account_id}:root"]
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

resource "aws_iam_role" "security_audit_role" {
  provider           = aws.workload
  name               = "SecurityAuditRole"
  assume_role_policy = data.aws_iam_policy_document.trust_policy.json
  description        = "Assumed by the Security account to run read-only audits of this Workload account"

  tags = {
    Project   = "IAM-Cross-Account-Access"
    ManagedBy = "Terraform"
  }
}

# Read-only, audit-focused permissions. AWS's managed SecurityAudit policy
# is purpose-built for this: it can read config/logging/IAM posture but
# cannot modify or delete anything or read data-plane content (e.g. S3 object
# bodies, DynamoDB items).
resource "aws_iam_role_policy_attachment" "security_audit_attach" {
  provider   = aws.workload
  role       = aws_iam_role.security_audit_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# ---------------------------------------------------------------------------
# 2. THE PERMISSION TO ASSUME IT — lives in the SECURITY account.
#    Being trusted by the role isn't enough; your IAM user/role in the
#    Security account also needs explicit sts:AssumeRole permission on it.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "can_assume_audit_role" {
  statement {
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.security_audit_role.arn]

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

resource "aws_iam_policy" "assume_audit_role_policy" {
  provider    = aws.security
  name        = "AssumeWorkloadSecurityAuditRole"
  description = "Grants permission to assume SecurityAuditRole in the Workload account"
  policy      = data.aws_iam_policy_document.can_assume_audit_role.json
}

# Attach that policy to the IAM user you configured via `aws configure`.
# We look the user up dynamically rather than hardcoding, so this works
# regardless of what you named your IAM user.
data "aws_caller_identity" "security" {
  provider = aws.security
}

data "aws_iam_user" "current_user" {
  provider  = aws.security
  user_name = split("/", data.aws_caller_identity.security.arn)[1]
}

resource "aws_iam_user_policy_attachment" "attach_to_current_user" {
  provider   = aws.security
  user       = data.aws_iam_user.current_user.user_name
  policy_arn = aws_iam_policy.assume_audit_role_policy.arn
}
