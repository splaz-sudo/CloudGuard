# CloudGuard AWS Read-Only Permissions Reference

This document describes the minimum AWS IAM permissions required for CloudGuard to perform read-only security scanning.

## Permission Categories

### REQUIRED — Core scanning functionality

These permissions are always required for any AWS scan.

| Action | Service | Collector | Reason | When Unavailable |
|--------|---------|-----------|--------|------------------|
| `sts:GetCallerIdentity` | STS | STS | Obtain caller account ID, ARN, and user ID for scan metadata | Scan cannot identify the target account; fails with credential error |
| `ec2:DescribeInstances` | EC2 | EC2 | Discover EC2 instances, their public/private IPs, IAM profiles, and security groups | No workload inventory; network exposure analysis impossible |
| `ec2:DescribeSecurityGroups` | EC2 | EC2 | Retrieve security group rules (ingress/egress) for network exposure analysis | No security group analysis; cannot determine public exposure |
| `s3:ListBuckets` | S3 | S3 | Enumerate all S3 buckets in the account | No storage inventory; sensitive bucket detection impossible |
| `s3:GetBucketLocation` | S3 | S3 | Determine bucket region for regional asset correlation | Buckets appear without region metadata |
| `iam:ListRoles` | IAM | IAM | Enumerate IAM roles for identity and privilege analysis | No role inventory; attack paths through roles impossible |
| `iam:ListAttachedRolePolicies` | IAM | IAM | Discover managed policies attached to roles | No effective permissions analysis for roles |
| `iam:GetPolicy` | IAM | IAM | Retrieve managed policy documents | Cannot analyze policy permissions |
| `iam:GetPolicyVersion` | IAM | IAM | Retrieve specific policy version document | Cannot analyze policy permissions |
| `iam:ListUsers` | IAM | IAM | Enumerate IAM users for identity analysis | No user inventory |
| `iam:ListAttachedUserPolicies` | IAM | IAM | Discover managed policies attached to users | No effective permissions analysis for users |
| `iam:ListInstanceProfiles` | IAM | IAM | Enumerate instance profiles linking EC2 to roles | Cannot link EC2 workloads to IAM roles |

### OPTIONAL — Enhanced analysis when available

| Action | Service | Collector | Reason | When Unavailable |
|--------|---------|-----------|--------|------------------|
| `s3:GetPublicAccessBlock` | S3 | S3 | Check bucket public access block configuration | Public access status unknown; bucket marked as unknown exposure |
| `s3:GetBucketPolicyStatus` | S3 | S3 | Check if bucket policy is public | Public policy status unknown |
| `s3:GetBucketTagging` | S3 | S3 | Read bucket tags for sensitive classification | Tag-based sensitive classification disabled |
| `ec2:DescribeVpcs` | EC2 | EC2 | VPC metadata for network topology | VPC context missing from network analysis |
| `ec2:DescribeSubnets` | EC2 | EC2 | Subnet metadata (CIDR, AZ, route table associations) | Subnet-level exposure analysis limited |
| `ec2:DescribeRouteTables` | EC2 | EC2 | Route table entries for Internet reachability | Cannot verify IGW routes; exposure may be over-reported |
| `ec2:DescribeInternetGateways` | EC2 | EC2 | Internet gateway presence for VPC | Internet reachability inference limited |
| `ec2:DescribeNatGateways` | EC2 | EC2 | NAT gateway presence for private subnet routing | Private subnet egress analysis limited |
| `ec2:DescribeNetworkAcls` | EC2 | EC2 | Network ACL rules for additional exposure context | ACL-based exposure analysis disabled |
| `ec2:DescribeNetworkInterfaces` | EC2 | EC2 | ENI metadata linking instances to subnets/SGs | Instance-to-subnet/SG correlation weakened |
| `ec2:DescribeAddresses` | EC2 | EC2 | Elastic IP metadata | EIP context missing |
| `iam:ListGroups` | IAM | IAM | IAM group membership for users | Group-based permissions not analyzed |
| `iam:ListGroupPolicies` | IAM | IAM | Inline group policies | Group inline policies not analyzed |
| `iam:ListRolePolicies` | IAM | IAM | Inline role policies | Role inline policies not analyzed |
| `iam:ListUserPolicies` | IAM | IAM | Inline user policies | User inline policies not analyzed |
| `iam:GetRole` | IAM | IAM | Role trust policy document | Cross-account trust analysis impossible |
| `iam:SimulatePrincipalPolicy` | IAM | IAM | Effective permission evaluation | Advanced IAM simulation unavailable |
| `iam:GetAccountAuthorizationDetails` | IAM | IAM | Bulk authorization details | Alternative to multiple list/get calls |

### FEATURE-SPECIFIC — Required for specific advanced features

| Action | Service | Feature | Reason |
|--------|---------|---------|--------|
| `rds:DescribeDBInstances` | RDS | RDS inventory | Database instance discovery |
| `rds:DescribeDBClusters` | RDS | RDS inventory | Aurora cluster discovery |
| `lambda:ListFunctions` | Lambda | Lambda inventory | Function discovery |
| `lambda:GetPolicy` | Lambda | Lambda cross-account | Resource-based policy analysis |
| `elasticloadbalancing:DescribeLoadBalancers` | ELBv2 | Network exposure 2.0 | Load balancer exposure analysis |
| `elasticloadbalancing:DescribeTargetGroups` | ELBv2 | Network exposure 2.0 | Target group backend analysis |
| `apigateway:GetRestApis` | API Gateway | API inventory | REST API discovery |
| `apigatewayv2:GetApis` | API Gateway v2 | API inventory | HTTP/WebSocket API discovery |
| `cloudfront:ListDistributions` | CloudFront | Edge exposure | Distribution discovery |
| `ecs:ListClusters` | ECS | Container inventory | Cluster discovery |
| `ecs:ListServices` | ECS | Container inventory | Service discovery |
| `eks:ListClusters` | EKS | Kubernetes inventory | Cluster discovery |
| `kms:ListKeys` | KMS | Key metadata | Key inventory (no key material) |
| `kms:DescribeKey` | KMS | Key metadata | Key metadata (no key material) |
| `secretsmanager:ListSecrets` | Secrets Manager | Secret metadata | Secret inventory (no values) |
| `cloudtrail:DescribeTrails` | CloudTrail | Trail status | Logging configuration check |
| `config:DescribeConfigurationRecorders` | Config | Config status | Configuration recording check |
| `guardduty:ListDetectors` | GuardDuty | GuardDuty status | Threat detection status |

## Reference Read-Only IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudGuardRequiredSts",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudGuardRequiredEc2",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudGuardRequiredS3",
      "Effect": "Allow",
      "Action": [
        "s3:ListBuckets",
        "s3:GetBucketLocation"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudGuardRequiredIam",
      "Effect": "Allow",
      "Action": [
        "iam:ListRoles",
        "iam:ListAttachedRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListUsers",
        "iam:ListAttachedUserPolicies",
        "iam:ListInstanceProfiles"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudGuardOptionalS3",
      "Effect": "Allow",
      "Action": [
        "s3:GetPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketTagging"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudGuardOptionalEc2Network",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeAddresses"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudGuardOptionalIamDetails",
      "Effect": "Allow",
      "Action": [
        "iam:ListGroups",
        "iam:ListGroupPolicies",
        "iam:ListRolePolicies",
        "iam:ListUserPolicies",
        "iam:GetRole"
      ],
      "Resource": "*"
    }
  ]
}
```

## Credential Configuration

CloudGuard uses the standard AWS SDK credential provider chain. No custom credential handling is implemented.

Supported credential sources (in priority order):

1. **Environment variables** — `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
2. **Shared credentials file** — `~/.aws/credentials` (profile specified via `CLOUDGUARD_AWS_PROFILE` or `AWS_PROFILE`)
3. **Shared config file** — `~/.aws/config` (region, role ARN, external ID)
4. **EC2/ECS instance profile** — When running on AWS compute
5. **SSO cached credentials** — `aws sso login` session

### Profile Configuration

```bash
# Environment variable
export CLOUDGUARD_AWS_PROFILE=cloudguard

# Or AWS standard
export AWS_PROFILE=cloudguard
```

### Region Configuration

```bash
# Comma-separated list
export CLOUDGUARD_AWS_REGIONS=us-east-1,us-west-2,eu-west-1

# Or single region via standard variable
export AWS_DEFAULT_REGION=us-east-1
```

### Cross-Account Role Assumption (where implemented)

```ini
# ~/.aws/config
[profile cloudguard-cross-account]
role_arn = arn:aws:iam::123456789012:role/CloudGuardReadOnly
source_profile = cloudguard
external_id = optional-external-id
region = us-east-1
```

## Behavior When Permissions Are Missing

| Missing Permission | Scan Result | Recorded As |
|-------------------|-------------|-------------|
| `sts:GetCallerIdentity` | FAILED | `credentials_invalid` / `access_denied` |
| `ec2:DescribeInstances` | PARTIAL | Collector `ec2` failed in affected region |
| `ec2:DescribeSecurityGroups` | PARTIAL | Collector `ec2` failed in affected region |
| `s3:ListBuckets` | PARTIAL | Collector `s3` failed |
| `iam:ListRoles` | PARTIAL | Collector `iam` failed |
| `iam:GetPolicy` | PARTIAL | Collector `iam` failed (attached policy fetch) |
| Optional permissions (e.g., `s3:GetPublicAccessBlock`) | COMPLETED | Coverage limitation recorded; scan continues |

## Cross-Account Scanning (Future)

When cross-account scanning is implemented via `sts:AssumeRole`:

- Temporary credentials are **ephemeral** — never persisted to database or logs
- `sts:AssumeRole` requires the role ARN and optionally `external_id`
- The assumed role must have the same read-only permissions documented above
- Role session name includes scan ID for CloudTrail correlation

## Security Notes

1. **No write permissions** — This policy contains only read/list/get/describe actions
2. **No secret retrieval** — No `secretsmanager:GetSecretValue`, `kms:Decrypt`, or equivalent
3. **No resource modification** — No `ec2:AuthorizeSecurityGroupIngress`, `iam:PutRolePolicy`, etc.
4. **Principle of least privilege** — Each permission is explicitly justified above
5. **Audit regularly** — Re-verify against actual CloudGuard collector code when adding features

## Testing the Policy

```bash
# Dry-run with AWS CLI (requires valid credentials)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:role/CloudGuardReadOnly \
  --action-names sts:GetCallerIdentity ec2:DescribeInstances s3:ListBuckets iam:ListRoles
```

## Version

This document reflects CloudGuard collector implementation as of the current codebase. Update when collectors change.