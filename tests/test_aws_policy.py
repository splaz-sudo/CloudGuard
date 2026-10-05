import json
import pytest


def test_reference_policy_contains_no_mutating_permissions():
    """
    Validate that the reference read-only policy contains
    no AWS mutating permissions.

    This test ensures the policy in
    deploy/cloudguard-readonly-policy.json remains
    strictly read-only.
    """
    policy_path = "deploy/cloudguard-readonly-policy.json"

    with open(policy_path) as f:
        policy = json.load(f)

    # Mutating action prefixes that must not appear
    mutating_prefixes = {
        "Create",
        "Delete",
        "Put",
        "Attach",
        "Detach",
        "Update",
        "Modify",
        "Add",
        "Remove",
        "Enable",
        "Disable",
        "Start",
        "Stop",
        "Terminate",
        "Reboot",
        "Run",
        "Launch",
        "Register",
        "Deregister",
        "Associate",
        "Disassociate",
        "Authorize",
        "Revoke",
        "Import",
        "Export",
        "Copy",
        "Move",
        "Rename",
        "Set",
        "Reset",
        "Change",
        "Upload",
        "Write",
        "Patch",
        "Post",
        "Purchase",
        "Request",
        "Cancel",
        "Accept",
        "Reject",
        "Approve",
        "Deny",
        "Grant",
        "Revoke",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "PutRolePolicy",
        "DeleteRolePolicy",
        "PutUserPolicy",
        "DeleteUserPolicy",
        "PutGroupPolicy",
        "DeleteGroupPolicy",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "AttachGroupPolicy",
        "DetachGroupPolicy",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        "PutObject",
        "DeleteObject",
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupEgress",
        "CreateSecurityGroup",
        "DeleteSecurityGroup",
        "CreateVpc",
        "DeleteVpc",
        "CreateSubnet",
        "DeleteSubnet",
        "CreateRouteTable",
        "DeleteRouteTable",
        "CreateRoute",
        "DeleteRoute",
        "CreateInternetGateway",
        "DeleteInternetGateway",
        "AttachInternetGateway",
        "DetachInternetGateway",
        "CreateNatGateway",
        "DeleteNatGateway",
        "CreateNetworkAcl",
        "DeleteNetworkAcl",
        "CreateNetworkAclEntry",
        "DeleteNetworkAclEntry",
        "CreateNetworkInterface",
        "DeleteNetworkInterface",
        "AllocateAddress",
        "ReleaseAddress",
        "AssociateAddress",
        "DisassociateAddress",
        "CreateLoadBalancer",
        "DeleteLoadBalancer",
        "CreateTargetGroup",
        "DeleteTargetGroup",
        "RegisterTargets",
        "DeregisterTargets",
        "CreateListener",
        "DeleteListener",
        "CreateRestApi",
        "DeleteRestApi",
        "CreateDeployment",
        "DeleteDeployment",
        "CreateDistribution",
        "DeleteDistribution",
        "CreateCluster",
        "DeleteCluster",
        "CreateService",
        "DeleteService",
        "RunTask",
        "StopTask",
        "CreateFunction",
        "DeleteFunction",
        "UpdateFunctionCode",
        "UpdateFunctionConfiguration",
        "AddPermission",
        "RemovePermission",
        "CreateKey",
        "ScheduleKeyDeletion",
        "EnableKeyRotation",
        "DisableKeyRotation",
        "PutKeyPolicy",
        "CreateSecret",
        "DeleteSecret",
        "PutSecretValue",
        "GetSecretValue",
        "CreateTrail",
        "DeleteTrail",
        "StartLogging",
        "StopLogging",
        "PutConfigurationRecorder",
        "DeleteConfigurationRecorder",
        "CreateDetector",
        "DeleteDetector",
        "CreatePolicy",
        "DeletePolicy",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "AttachGroupPolicy",
        "DetachGroupPolicy",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "PutRolePolicy",
        "DeleteRolePolicy",
        "UpdateAssumeRolePolicy",
        "CreateRole",
        "DeleteRole",
        "CreateUser",
        "DeleteUser",
        "CreateAccessKey",
        "DeleteAccessKey",
        "UpdateAccessKey",
        "CreateLoginProfile",
        "DeleteLoginProfile",
        "UpdateLoginProfile",
        "CreateInstanceProfile",
        "DeleteInstanceProfile",
        "AddRoleToInstanceProfile",
        "RemoveRoleFromInstanceProfile",
        "TagResource",
        "UntagResource",
    }

    # Additional specific mutating actions
    mutating_exact = {
        "sts:AssumeRole",  # This is read in some contexts but write-like; flag for review
    }

    errors = []

    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            # Check exact mutating matches
            if action in mutating_exact:
                errors.append(
                    f"Mutating action found: {action}"
                )

            # Check mutating prefixes
            for prefix in mutating_prefixes:
                if action.startswith(prefix + ":") or action == prefix:
                    # Allow known safe actions that happen to start with these prefixes
                    safe_exceptions = {
                        "s3:GetBucketLocation",
                        "s3:GetBucketPolicyStatus",
                        "s3:GetPublicAccessBlock",
                        "s3:GetBucketTagging",
                        "s3:ListBuckets",
                        "iam:GetPolicy",
                        "iam:GetPolicyVersion",
                        "iam:GetRole",
                        "iam:ListRoles",
                        "iam:ListUsers",
                        "iam:ListGroups",
                        "iam:ListAttachedRolePolicies",
                        "iam:ListAttachedUserPolicies",
                        "iam:ListAttachedGroupPolicies",
                        "iam:ListRolePolicies",
                        "iam:ListUserPolicies",
                        "iam:ListGroupPolicies",
                        "iam:ListInstanceProfiles",
                        "iam:ListRoles",
                        "iam:ListUsers",
                        "iam:SimulatePrincipalPolicy",
                        "iam:GetAccountAuthorizationDetails",
                        "ec2:DescribeInstances",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeVpcs",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeRouteTables",
                        "ec2:DescribeInternetGateways",
                        "ec2:DescribeNatGateways",
                        "ec2:DescribeNetworkAcls",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeAddresses",
                        "ec2:DescribeLoadBalancers",
                        "ec2:DescribeTargetGroups",
                        "sts:GetCallerIdentity",
                        "ec2:Get*",  # wildcard for read-only
                    }
                    if action not in safe_exceptions:
                        # Check if it's a read-only describe/list/get pattern
                        is_read_only = any(
                            action.startswith(safe_prefix)
                            for safe_prefix in [
                                "Describe", "List", "Get", "Head",
                                "Check", "View", "Read", "Preview",
                                "Scan", "Search", "Query", "Filter",
                                "Select", "Count", "Fetch", "Retrieve",
                                "Lookup", "Resolve", "Verify", "Validate",
                                "Test", "Simulate", "DryRun"
                            ]
                        )
                        if not is_read_only:
                            errors.append(
                                f"Potentially mutating action: {action}"
                            )

    assert not errors, (
        "Reference policy contains potentially mutating permissions:\n"
        + "\n".join(errors)
    )


def test_policy_contains_required_permissions():
    """
    Verify the policy includes the known required permissions
    for CloudGuard core functionality.
    """
    policy_path = "deploy/cloudguard-readonly-policy.json"

    with open(policy_path) as f:
        policy = json.load(f)

    required_actions = {
        "sts:GetCallerIdentity",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "s3:ListBuckets",
        "s3:GetBucketLocation",
        "iam:ListRoles",
        "iam:ListAttachedRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListUsers",
        "iam:ListAttachedUserPolicies",
        "iam:ListInstanceProfiles",
    }

    allowed_actions = set()
    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        allowed_actions.update(actions)

    missing = required_actions - allowed_actions
    assert not missing, f"Missing required permissions: {missing}"


def test_policy_structure():
    """
    Basic structural validation of the policy document.
    """
    policy_path = "deploy/cloudguard-readonly-policy.json"

    with open(policy_path) as f:
        policy = json.load(f)

    assert policy.get("Version") == "2012-10-17"
    assert "Statement" in policy
    assert isinstance(policy["Statement"], list)
    assert len(policy["Statement"]) > 0

    for statement in policy["Statement"]:
        assert "Effect" in statement
        assert statement["Effect"] in ("Allow", "Deny")
        assert "Action" in statement or "NotAction" in statement
        assert "Resource" in statement or "NotResource" in statement