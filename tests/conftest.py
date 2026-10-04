import pytest

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
from cloudguard.services.analysis import (
    AnalysisService,
)

ACCOUNT_ID = LocalAWSLab.ACCOUNT_ID
REGION = LocalAWSLab.REGION


@pytest.fixture()
def analysis_service():
    return AnalysisService()


@pytest.fixture()
def local_lab_analysis(analysis_service):
    return (
        analysis_service
        .analyze_local_lab()
    )


@pytest.fixture()
def build_analysis(analysis_service):
    """
    Factory fixture building an AnalysisResult
    from collector-level environment objects.
    """

    def _build(
        *,
        instances,
        security_groups,
        buckets,
        roles,
        instance_profiles,
    ):
        return (
            analysis_service
            .analyze_environment(
                instances=instances,
                security_groups=(
                    security_groups
                ),
                buckets=buckets,
                roles=roles,
                instance_profiles=(
                    instance_profiles
                ),
                account_id=ACCOUNT_ID,
            )
        )

    return _build


def make_bucket(
    name="customer-backups",
    sensitive=True,
):
    tags = {"Project": "CloudGuard"}

    if sensitive:
        tags["CloudGuardSensitive"] = "true"
        tags["DataClassification"] = (
            "confidential"
        )

    return S3Bucket(
        name=name,
        region=REGION,
        public_access_block_enabled=True,
        policy_public=False,
        tags=tags,
    )


def make_role(
    name,
    actions,
    bucket_name,
):
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    return IAMRole(
        name=name,
        arn=(
            f"arn:aws:iam::{ACCOUNT_ID}"
            f":role/{name}"
        ),
        role_id="AROATEST",
        attached_policies=[
            IAMPolicy(
                name=f"{name}-policy",
                arn=(
                    f"arn:aws:iam::{ACCOUNT_ID}"
                    f":policy/{name}-policy"
                ),
                statements=[
                    IAMPolicyStatement(
                        effect="Allow",
                        actions=list(actions),
                        resources=[
                            f"{bucket_arn}/*"
                        ],
                    ),
                ],
            )
        ],
    )


def make_profile(name, role_names):
    return InstanceProfile(
        name=name,
        arn=(
            f"arn:aws:iam::{ACCOUNT_ID}"
            f":instance-profile/{name}"
        ),
        role_names=list(role_names),
    )


def make_open_security_group(
    group_id,
    port=80,
):
    return SecurityGroup(
        group_id=group_id,
        group_name=f"{group_id}-name",
        vpc_id="vpc-test",
        inbound_rules=[
            SecurityGroupRule(
                protocol="tcp",
                from_port=port,
                to_port=port,
                sources=["0.0.0.0/0"],
            )
        ],
    )


def make_instance(
    instance_id,
    security_group_ids,
    profile_arn=None,
    public_ip="203.0.113.10",
):
    return EC2Instance(
        instance_id=instance_id,
        instance_type="t3.micro",
        state="running",
        region=REGION,
        public_ip=public_ip,
        private_ip="10.50.1.10",
        iam_instance_profile_arn=(
            profile_arn
        ),
        security_group_ids=list(
            security_group_ids
        ),
    )
