# Lab 01 — IAM Least-Privilege Review Checklist

**Goal:** find the three most common IAM hygiene problems in an AWS account
using read-only AWS CLI commands: users without MFA, wildcard (`*`) policies,
and stale access keys.

**Time:** ~20 minutes. **Risk:** none — every command below is read-only.

## Prerequisites

- AWS CLI v2 configured with read-only IAM permissions
  (`iam:List*`, `iam:Get*` are enough)
- A sandbox or personal account — never production for practice

## Exercise

### 1. Users without MFA

```bash
# List all IAM users
aws iam list-users --query 'Users[].UserName' --output text

# Check each user for MFA devices (empty output = no MFA enrolled)
for u in $(aws iam list-users --query 'Users[].UserName' --output text); do
  echo "== $u =="
  aws iam list-mfa-devices --user-name "$u" --query 'MFADevices[].SerialNumber' --output text
done
```

**Pass criteria:** every human user has at least one MFA device. Flag any
without.

### 2. Wildcard policies

```bash
# List customer-managed policies and inspect their statements
aws iam list-policies --scope Local --query 'Policies[].[PolicyName,Arn]' --output text
```

Pick each policy and look for `"Action": "*"` paired with `"Resource": "*"`:

```bash
aws iam get-policy-version \
  --policy-arn <policy-arn> \
  --version-id v1 \
  --query 'PolicyVersion.Document.Statement'
```

**Pass criteria:** no customer-managed policy grants `*` on `*`. Each
wildcard you find is a finding — note what it was probably created for.

### 3. Stale access keys

```bash
# Generate the credential report, then download it
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d > credential-report.csv
```

Open the CSV and check `access_key_1_last_used_date` /
`access_key_2_last_used_date` and `access_key_*_last_rotated`. Flag keys
unused for 90+ days or never rotated.

**Pass criteria:** no active key older than 90 days without a documented
reason.

## What "done" looks like

A short findings list, for example:

| # | Finding | Severity | Recommendation |
|---|---------|----------|----------------|
| 1 | `deploy-bot` has no MFA | High | Enroll virtual MFA or move to IAM role |
| 2 | `DevPowerUser` allows `*` on `*` | High | Scope to required services |
| 3 | Key for `reports` unused 214 days | Medium | Deactivate, then delete after 7 days |

## Cleanup

None needed — this lab makes no changes.

## Next

Lab 02 (EC2 hardening baseline) builds on this: once identities are tight,
harden what they can reach.
