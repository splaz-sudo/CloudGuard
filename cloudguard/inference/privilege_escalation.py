"""
IAM Privilege Escalation Analysis

Implements rule-based privilege escalation analysis based on
well-known IAM escalation primitives and combinations.

This is read-only static analysis - NEVER executes any escalation.

Analyzes combinations such as:
- iam:PassRole + service execution capability
- iam:CreatePolicyVersion + iam:SetDefaultPolicyVersion
- iam:AttachUserPolicy / iam:AttachRolePolicy
- iam:PutUserPolicy / iam:PutRolePolicy
- iam:UpdateAssumeRolePolicy
- iam:CreateAccessKey + iam:UpdateAccessKey
- And other well-established IAM escalation primitives

Models potential escalation relationships in the security graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from cloudguard.collectors.iam import (
    IAMPolicy,
    IAMPolicyStatement,
    IAMRole,
    IAMUser,
)
from cloudguard.inference.iam_analysis import IAMFinding, IAMFindingType


class EscalationType(str, Enum):
    """Types of privilege escalation paths."""
    PASS_ROLE = "pass_role"
    CREATE_POLICY_VERSION = "create_policy_version"
    ATTACH_USER_POLICY = "attach_user_policy"
    ATTACH_ROLE_POLICY = "attach_role_policy"
    PUT_USER_POLICY = "put_user_policy"
    PUT_ROLE_POLICY = "put_role_policy"
    UPDATE_ASSUME_ROLE_POLICY = "update_assume_role_policy"
    CREATE_ACCESS_KEY = "create_access_key"
    UPDATE_ACCESS_KEY = "update_access_key"
    CREATE_POLICY_VERSION = "create_policy_version"
    SET_DEFAULT_POLICY_VERSION = "set_default_policy_version"
    PUT_USER_POLICY = "put_user_policy"
    PUT_ROLE_POLICY = "put_role_policy"
    UPDATE_ASSUME_ROLE_POLICY = "update_assume_role_policy"
    USER_DATA = "user_data"


class EscalationPrerequisite(str, Enum):
    """Prerequisites that must be satisfied for escalation."""
    CAN_PASS_ROLE = "can_pass_role"
    CAN_CREATE_POLICY_VERSION = "can_create_policy_version"
    CAN_SET_DEFAULT_POLICY_VERSION = "can_set_default_policy_version"
    CAN_ATTACH_USER_POLICY = "can_attach_user_policy"
    CAN_ATTACH_ROLE_POLICY = "can_attach_role_policy"
    CAN_PUT_USER_POLICY = "can_put_user_policy"
    CAN_PUT_ROLE_POLICY = "can_put_role_policy"
    CAN_UPDATE_ASSUME_ROLE_POLICY = "can_update_assume_role_policy"
    CAN_CREATE_ACCESS_KEY = "can_create_access_key"
    CAN_UPDATE_ACCESS_KEY = "can_update_access_key"
    CAN_RUN_INSTANCES = "can_run_instances"
    CAN_PASS_ROLE_TO_SERVICE = "can_pass_role_to_service"
    HAS_PERMISSIONS_BOUNDARY = "has_permissions_boundary"


@dataclass
class EscalationPath:
    """A potential privilege escalation path with evidence."""
    escalation_type: str
    principal_id: str
    principal_type: str  # "user" or "role"
    principal_name: str
    required_prerequisites: list[str]
    satisfied_prerequisites: list[str]
    missing_prerequisites: list[str]
    target_resource: str | None = None
    evidence: str = ""
    confidence: str = "LOW"  # HIGH, MEDIUM, LOW
    limitations: list[str] = field(default_factory=list)


@dataclass
class EscalationFinding:
    """A privilege escalation finding."""
    escalation_type: str
    principal_id: str
    principal_type: str
    principal_name: str
    severity: str
    evidence: str
    prerequisites: list[str]
    satisfied: list[str]
    missing: list[str]
    confidence: str
    limitations: list[str]
    policy_arn: str | None = None
    policy_name: str | None = None
    statement: dict | None = None


# Well-known privilege escalation techniques
# Based on research by Rhino Security Labs, AWS documentation, and community knowledge
ESCALATION_TECHNIQUES = {
    "pass_role_ec2": {
        "name": "PassRole to EC2",
        "description": "Pass an IAM role to EC2 instance to assume its permissions",
        "required_actions": [
            "iam:PassRole",
            "ec2:RunInstances",
        ],
        "prerequisites": [
            "iam:PassRole on a privileged role",
            "ec2:RunInstances",
        ],
        "confidence": "HIGH",
    },
    "pass_role_lambda": {
        "name": "PassRole to Lambda",
        "description": "Create Lambda function with a privileged role",
        "required_actions": [
            "iam:PassRole",
            "lambda:CreateFunction",
        ],
        "prerequisites": [
            "iam:PassRole on a privileged role",
            "lambda:CreateFunction",
        ],
        "confidence": "HIGH",
    },
    "pass_role_ecs": {
        "name": "PassRole to ECS",
        "description": "Run ECS task with a privileged role",
        "required_actions": [
            "iam:PassRole",
            "ecs:RunTask",
        ],
        "prerequisites": [
            "iam:PassRole on a privileged role",
            "ecs:RunTask",
        ],
        "confidence": "HIGH",
    },
    "create_policy_version": {
        "name": "Create Policy Version",
        "description": "Create new version of managed policy and set as default",
        "required_actions": [
            "iam:CreatePolicyVersion",
            "iam:SetDefaultPolicyVersion",
        ],
        "prerequisites": [
            "iam:CreatePolicyVersion on a managed policy",
            "iam:SetDefaultPolicyVersion on same policy",
        ],
        "confidence": "HIGH",
    },
    "attach_user_policy": {
        "name": "Attach User Policy",
        "description": "Attach managed policy with elevated permissions to user",
        "required_actions": [
            "iam:AttachUserPolicy",
        ],
        "prerequisites": [
            "iam:AttachUserPolicy on a privileged policy",
        ],
        "confidence": "MEDIUM",
    },
    "attach_role_policy": {
        "name": "Attach Role Policy",
        "description": "Attach managed policy with elevated permissions to role",
        "required_actions": [
            "iam:AttachRolePolicy",
        ],
        "prerequisites": [
            "iam:AttachRolePolicy on a privileged policy",
        ],
        "confidence": "MEDIUM",
    },
    "put_user_policy": {
        "name": "Put User Inline Policy",
        "description": "Add inline policy with elevated permissions to user",
        "required_actions": [
            "iam:PutUserPolicy",
        ],
        "prerequisites": [
            "iam:PutUserPolicy",
        ],
        "confidence": "MEDIUM",
    },
    "put_role_policy": {
        "name": "Put Role Inline Policy",
        "description": "Add inline policy with elevated permissions to role",
        "required_actions": [
            "iam:PutRolePolicy",
        ],
        "prerequisites": [
            "iam:PutRolePolicy",
        ],
        "confidence": "MEDIUM",
    },
    "update_assume_role_policy": {
        "name": "Update Assume Role Policy",
        "description": "Modify role trust policy to allow self to assume",
        "required_actions": [
            "iam:UpdateAssumeRolePolicy",
        ],
        "prerequisites": [
            "iam:UpdateAssumeRolePolicy on a privileged role",
        ],
        "confidence": "HIGH",
    },
    "create_access_key": {
        "name": "Create Access Key",
        "description": "Create access key for another user/role",
        "required_actions": [
            "iam:CreateAccessKey",
        ],
        "prerequisites": [
            "iam:CreateAccessKey on another identity",
        ],
        "confidence": "MEDIUM",
    },
    "update_access_key": {
        "name": "Update Access Key",
        "description": "Reactivate compromised/inactive access key",
        "required_actions": [
            "iam:UpdateAccessKey",
        ],
        "prerequisites": [
            "iam:UpdateAccessKey on another identity's key",
        ],
        "confidence": "LOW",
    },
    "user_data": {
        "name": "EC2 User Data",
        "description": "Inject commands via EC2 user data when launching instance with role",
        "required_actions": [
            "ec2:RunInstances",
            "iam:PassRole",
        ],
        "prerequisites": [
            "ec2:RunInstances",
            "iam:PassRole on a privileged role",
        ],
        "confidence": "HIGH",
    },
}


class PrivilegeEscalationAnalyzer:
    """
    Analyzes IAM configurations for privilege escalation paths.

    Implements rule-based analysis of well-known IAM privilege
    escalation techniques. Does NOT execute any escalation -
    this is read-only static analysis only.

    Models potential escalation relationships in the security graph.
    """

    def __init__(self):
        self.techniques = ESCALATION_TECHNIQUES

    def analyze(
        self,
        roles: list,
        users: list,
        policies: list = None,
        instance_profiles: list = None,
    ) -> list:
        """
        Analyze IAM configurations for privilege escalation paths.

        Returns list of EscalationPath objects.
        """
        escalation_paths = []

        # Build lookups
        roles_by_name = {r.name: r for r in roles}
        roles_by_arn = {r.arn: r for r in roles}
        users_by_name = {u.name: u for u in users}
        users_by_arn = {u.arn: u for u in users}

        # Analyze each user
        for user in users:
            paths = self._analyze_user_escalation(
                user, users, roles
            )
            escalation_paths.extend(paths)

        # Analyze each role
        for role in roles:
            paths = self._analyze_role_escalation(
                role, roles, users
            )
            escalation_paths.extend(paths)

        # Analyze instance profiles
        for profile in (instance_profiles or []):
            paths = self._analyze_instance_profile_escalation(
                profile, roles, users
            )
            escalation_paths.extend(paths)

        return escalation_paths

    def _analyze_user_escalation(
        self,
        user,
        users: list,
        roles: list,
    ) -> list:
        """Analyze privilege escalation paths for a user."""
        paths = []

        # Get all permissions for this user (direct + groups)
        user_permissions = self._get_user_permissions(user)

        # Check each escalation technique
        for tech_key, tech in self.techniques.items():
            path = self._check_technique(
                principal_id=user.user_id,
                principal_type="user",
                principal_name=user.name,
                user_permissions=user_permissions,
                technique=tech,
                technique_key=tech_key,
            )
            if path:
                paths.append(path)

        return paths

    def _analyze_role_escalation(
        self,
        role,
        roles: list,
        users: list,
    ) -> list:
        """Analyze privilege escalation paths for a role."""
        paths = []

        # Get all permissions for this role
        role_permissions = self._get_role_permissions(role)

        # Check each escalation technique
        for tech_key, tech in self.techniques.items():
            path = self._check_technique(
                principal_id=role.role_id,
                principal_type="role",
                principal_name=role.name,
                user_permissions=role_permissions,
                technique=tech,
                technique_key=tech_key,
            )
            if path:
                paths.append(path)

        return paths

    def _analyze_instance_profile_escalation(
        self,
        profile,
        roles: list,
        users: list,
    ) -> list:
        """Analyze privilege escalation via instance profile."""
        paths = []

        # An instance profile with a privileged role can be passed to EC2
        for role_name in profile.role_names:
            role = next((r for r in roles if r.name == role_name), None)
            if role:
                role_permissions = self._get_role_permissions(role)

                # Check if this profile enables ec2:RunInstances + iam:PassRole
                for tech_key, tech in self.techniques.items():
                    if "ec2:RunInstances" in tech.get("required_actions", []) or \
                       "ec2:RunInstances" in tech.get("prerequisites", []):
                        path = self._check_technique(
                            principal_id=profile.arn,
                            principal_type="instance_profile",
                            principal_name=profile.name,
                            user_permissions=role_permissions,
                            technique=tech,
                            technique_key=tech_key,
                        )
                        if path:
                            path.principal_type = "instance_profile"
                            path.principal_name = f"{profile.name} -> {role_name}"
                            paths.append(path)

        return paths

    def _get_user_permissions(self, user) -> set:
        """Get all permissions for a user (direct + groups)."""
        permissions = set()

        # Direct attached policies
        for policy in user.attached_policies:
            for statement in policy.statements:
                if statement.effect.lower() == "allow":
                    permissions.update(self._extract_actions(statement))

        return permissions

    def _get_role_permissions(self, role) -> set:
        """Get all permissions for a role."""
        permissions = set()

        for policy in role.attached_policies:
            for statement in policy.statements:
                if statement.effect.lower() == "allow":
                    permissions.update(self._extract_actions(statement))

        return permissions

    def _extract_actions(self, statement) -> set:
        """Extract actions from a policy statement."""
        actions = set()
        for action in statement.actions:
            if isinstance(action, str):
                actions.add(action)
            elif isinstance(action, list):
                actions.update(action)
        return actions

    def _check_technique(
        self,
        principal_id: str,
        principal_type: str,
        principal_name: str,
        user_permissions: set,
        technique: dict,
        technique_key: str,
    ):
        """Check if a privilege escalation technique is feasible."""
        required_actions = set(technique.get("required_actions", []))
        prerequisites = set(technique.get("prerequisites", []))

        # Check which required actions the principal has
        satisfied = user_permissions & required_actions
        missing = required_actions - satisfied

        # Check prerequisites (these are conditions, not direct permissions)
        # For now, we treat them as additional checks
        satisfied_prereqs = set()
        missing_prereqs = set(prerequisites)

        # Check if we can satisfy prerequisites
        # (This is simplified - real analysis would be more complex)
        for prereq in prerequisites:
            if prereq in required_actions and prereq in user_permissions:
                satisfied_prereqs.add(prereq)
                missing_prereqs.discard(prereq)

        # Determine if technique is feasible
        if required_actions and satisfied == required_actions:
            # All required actions are present - technique is feasible
            confidence = technique.get("confidence", "MEDIUM")
            return self._create_escalation_path(
                escalation_type=technique_key,
                principal_id=principal_id,
                principal_type=principal_type,
                principal_name=principal_name,
                required=list(required_actions),
                satisfied=list(satisfied),
                missing=list(missing),
                prerequisites=list(prerequisites),
                satisfied_prereqs=list(satisfied_prereqs),
                missing_prereqs=list(missing_prereqs),
                evidence=f"Principal has all required actions for {technique['name']}: {', '.join(satisfied)}",
                confidence=technique.get("confidence", "MEDIUM"),
            )
        elif satisfied and not missing:
            # Partial - has some required actions
            # This is a partial path
            confidence = "LOW"
            return self._create_escalation_path(
                escalation_type=technique_key,
                principal_id=principal_id,
                principal_type=principal_type,
                principal_name=principal_name,
                required=list(required_actions),
                satisfied=list(satisfied),
                missing=list(missing),
                prerequisites=list(prerequisites),
                satisfied_prereqs=list(satisfied_prereqs),
                missing_prereqs=list(missing_prereqs),
                evidence=f"Principal has some required actions for {technique['name']}: {', '.join(satisfied)}. Missing: {', '.join(missing)}",
                confidence="LOW",
            )

        return None

    def _create_escalation_path(
        self,
        escalation_type: str,
        principal_id: str,
        principal_type: str,
        principal_name: str,
        required: list,
        satisfied: list,
        missing: list,
        prerequisites: list,
        satisfied_prereqs: list,
        missing_prereqs: list,
        evidence: str,
        confidence: str,
    ):
        """Create an EscalationPath object."""
        return EscalationPath(
            escalation_type=escalation_type,
            principal_id=principal_id,
            principal_type=principal_type,
            principal_name=principal_name,
            required_prerequisites=prerequisites,
            satisfied_prerequisites=satisfied_prereqs,
            missing_prerequisites=missing_prereqs,
            evidence=evidence,
            confidence=confidence,
            limitations=[
                "Analysis is based on observed permissions only",
                "Does not evaluate IAM conditions",
                "Does not account for permissions boundaries",
                "Does not evaluate SCPs",
            ],
        )


def find_privilege_escalation_paths(
    roles: list,
    users: list,
    instance_profiles: list = None,
) -> list:
    """
    Convenience function to find all privilege escalation paths.

    Returns list of EscalationPath objects.
    """
    analyzer = PrivilegeEscalationAnalyzer()
    return analyzer.analyze(
        roles=roles,
        users=users,
        instance_profiles=instance_profiles,
    )