"""
CloudGuard LOCAL LAB scenarios.

Each scenario is a deterministic, simulated AWS
environment with known expected outcomes. No
AWS API calls are made and no AWS resources
are created.

Scenarios power LOCAL LAB scans, validation
tests, and rescan/comparison workflows (for
example scanning "public-ec2" and then
"remediated-lab" to verify a fix).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cloudguard.collectors.ec2 import (
    EC2Instance,
    SecurityGroup,
    SecurityGroupRule,
)
from cloudguard.collectors.iam import (
    IAMPolicy,
    IAMPolicyStatement,
    IAMRole,
    InstanceProfile,
)
from cloudguard.collectors.s3 import S3Bucket
from cloudguard.local_lab import LocalAWSLab

ACCOUNT_ID = LocalAWSLab.ACCOUNT_ID
REGION = LocalAWSLab.REGION


@dataclass
class LabEnvironment:
    account_id: str = ACCOUNT_ID
    region: str = REGION
    instances: list[EC2Instance] = field(
        default_factory=list
    )
    security_groups: list[SecurityGroup] = (
        field(default_factory=list)
    )
    buckets: list[S3Bucket] = field(
        default_factory=list
    )
    roles: list[IAMRole] = field(
        default_factory=list
    )
    instance_profiles: list[InstanceProfile] = (
        field(default_factory=list)
    )


@dataclass(frozen=True)
class LabScenario:
    name: str
    title: str
    description: str


SCENARIO_INFO: dict[str, LabScenario] = {
    "public-ec2": LabScenario(
        name="public-ec2",
        title="Public EC2 -> IAM Role -> Sensitive S3",
        description=(
            "The original CloudGuard lab: an "
            "internet-exposed EC2 workload whose "
            "role can read a sensitive bucket."
        ),
    ),
    "remediated-lab": LabScenario(
        name="remediated-lab",
        title="Remediated public-ec2",
        description=(
            "The public-ec2 scenario after the "
            "recommended fix: ingress is scoped "
            "to the VPC and the instance has no "
            "public IP."
        ),
    ),
    "two-exposed-workloads": LabScenario(
        name="two-exposed-workloads",
        title="Two exposed workloads",
        description=(
            "Two public instances; only one "
            "participates in an attack path."
        ),
    ),
    "broad-iam-role": LabScenario(
        name="broad-iam-role",
        title="Broad IAM permissions",
        description=(
            "Public EC2 whose role has write "
            "permissions on a sensitive bucket."
        ),
    ),
    "private-lab": LabScenario(
        name="private-lab",
        title="Private environment (negative)",
        description=(
            "No public exposure and no path to "
            "the sensitive bucket. CloudGuard "
            "should report no attack paths."
        ),
    ),
}

DEFAULT_SCENARIO = "public-ec2"


def scenario_names() -> list[str]:
    return sorted(SCENARIO_INFO)


def create_scenario_environment(
    name: str,
) -> LabEnvironment:
    if name not in SCENARIO_INFO:
        raise UnknownScenarioError(name)

    builder = _SCENARIO_BUILDERS[name]

    return builder()


class UnknownScenarioError(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(
            f"Unknown LOCAL LAB scenario: "
            f"{name}"
        )
        self.scenario = name


# --------------------------------------------------
# Builders
# --------------------------------------------------


def _sensitive_bucket() -> S3Bucket:
    return S3Bucket(
        name="customer-backups",
        region=REGION,
        public_access_block_enabled=True,
        policy_public=False,
        tags={
            "Project": "CloudGuard",
            "CloudGuardSensitive": "true",
            "DataClassification": "confidential",
        },
    )


def _read_role(bucket_name: str) -> IAMRole:
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    return IAMRole(
        name="cloudguard-web-role",
        arn=(
            f"arn:aws:iam::{ACCOUNT_ID}:role/"
            "cloudguard-web-role"
        ),
        role_id="AROACLOUDGUARDLOCAL",
        attached_policies=[
            IAMPolicy(
                name="CloudGuardS3ReadPolicy",
                arn=(
                    f"arn:aws:iam::{ACCOUNT_ID}"
                    ":policy/"
                    "CloudGuardS3ReadPolicy"
                ),
                statements=[
                    IAMPolicyStatement(
                        effect="Allow",
                        actions=["s3:ListBucket"],
                        resources=[bucket_arn],
                    ),
                    IAMPolicyStatement(
                        effect="Allow",
                        actions=["s3:GetObject"],
                        resources=[
                            f"{bucket_arn}/*"
                        ],
                    ),
                ],
            )
        ],
    )


def _profile(
    name: str,
    role_names: list[str],
) -> InstanceProfile:
    return InstanceProfile(
        name=name,
        arn=(
            f"arn:aws:iam::{ACCOUNT_ID}"
            f":instance-profile/{name}"
        ),
        role_names=list(role_names),
    )


def _open_group(
    group_id: str,
    port: int,
) -> SecurityGroup:
    return SecurityGroup(
        group_id=group_id,
        group_name=f"{group_id}-name",
        vpc_id="vpc-cloudguard-lab",
        inbound_rules=[
            SecurityGroupRule(
                protocol="tcp",
                from_port=port,
                to_port=port,
                sources=["0.0.0.0/0"],
            )
        ],
    )


def _instance(
    instance_id: str,
    group_ids: list[str],
    profile_arn: str | None = None,
    public_ip: str | None = "203.0.113.10",
) -> EC2Instance:
    return EC2Instance(
        instance_id=instance_id,
        instance_type="t3.micro",
        state="running",
        region=REGION,
        public_ip=public_ip,
        private_ip="10.50.1.10",
        iam_instance_profile_arn=profile_arn,
        security_group_ids=list(group_ids),
    )


def _build_public_ec2() -> LabEnvironment:
    lab = LocalAWSLab()

    (
        instances,
        security_groups,
        buckets,
        roles,
        instance_profiles,
    ) = lab.create_environment()

    return LabEnvironment(
        instances=list(instances),
        security_groups=list(security_groups),
        buckets=list(buckets),
        roles=list(roles),
        instance_profiles=list(
            instance_profiles
        ),
    )


def _build_remediated() -> LabEnvironment:
    environment = _build_public_ec2()

    environment.instances[0].public_ip = None

    environment.security_groups[
        0
    ].inbound_rules[0].sources = [
        "10.50.0.0/16"
    ]

    return environment


def _build_two_exposed() -> LabEnvironment:
    bucket = _sensitive_bucket()
    role = _read_role(bucket.name)
    profile = _profile(
        "cloudguard-web-profile",
        [role.name],
    )

    group_a = _open_group("sg-web-a", 80)
    group_b = _open_group("sg-web-b", 22)

    instance_a = _instance(
        "i-cloudguard-web-01",
        [group_a.group_id],
        profile_arn=profile.arn,
        public_ip="203.0.113.10",
    )

    instance_b = _instance(
        "i-cloudguard-web-02",
        [group_b.group_id],
        public_ip="203.0.113.11",
    )

    return LabEnvironment(
        instances=[instance_a, instance_b],
        security_groups=[group_a, group_b],
        buckets=[bucket],
        roles=[role],
        instance_profiles=[profile],
    )


def _build_broad_iam() -> LabEnvironment:
    bucket = _sensitive_bucket()

    bucket_arn = f"arn:aws:s3:::{bucket.name}"

    role = IAMRole(
        name="cloudguard-writer-role",
        arn=(
            f"arn:aws:iam::{ACCOUNT_ID}:role/"
            "cloudguard-writer-role"
        ),
        role_id="AROACLOUDGUARDWRITE",
        attached_policies=[
            IAMPolicy(
                name="CloudGuardS3WritePolicy",
                arn=(
                    f"arn:aws:iam::{ACCOUNT_ID}"
                    ":policy/"
                    "CloudGuardS3WritePolicy"
                ),
                statements=[
                    IAMPolicyStatement(
                        effect="Allow",
                        actions=[
                            "s3:GetObject",
                            "s3:PutObject",
                            "s3:DeleteObject",
                        ],
                        resources=[
                            f"{bucket_arn}/*"
                        ],
                    ),
                ],
            )
        ],
    )

    profile = _profile(
        "cloudguard-writer-profile",
        [role.name],
    )

    group = _open_group("sg-web", 80)

    instance = _instance(
        "i-cloudguard-web-01",
        [group.group_id],
        profile_arn=profile.arn,
    )

    return LabEnvironment(
        instances=[instance],
        security_groups=[group],
        buckets=[bucket],
        roles=[role],
        instance_profiles=[profile],
    )


def _build_private() -> LabEnvironment:
    bucket = _sensitive_bucket()
    role = _read_role(bucket.name)
    profile = _profile(
        "cloudguard-web-profile",
        [role.name],
    )

    group = _open_group("sg-web", 80)
    group.inbound_rules[0].sources = [
        "10.50.0.0/16"
    ]

    instance = _instance(
        "i-cloudguard-web-01",
        [group.group_id],
        profile_arn=profile.arn,
        public_ip=None,
    )

    return LabEnvironment(
        instances=[instance],
        security_groups=[group],
        buckets=[bucket],
        roles=[role],
        instance_profiles=[profile],
    )


_SCENARIO_BUILDERS = {
    "public-ec2": _build_public_ec2,
    "remediated-lab": _build_remediated,
    "two-exposed-workloads": _build_two_exposed,
    "broad-iam-role": _build_broad_iam,
    "private-lab": _build_private,
}
