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


class LocalAWSLab:
    """
    Creates a completely local simulated AWS environment.

    No AWS API calls are made.
    No AWS resources are created.
    No cloud credentials are required.

    The environment intentionally contains a security
    attack path:

        Internet
            ->
        EC2
            ->
        IAM Role
            ->
        Sensitive S3 Bucket
    """

    ACCOUNT_ID = "111122223333"
    REGION = "us-east-1"

    def create_environment(
        self,
    ) -> tuple[
        list[EC2Instance],
        list[SecurityGroup],
        list[S3Bucket],
        list[IAMRole],
        list[InstanceProfile],
    ]:
        security_groups = (
            self._create_security_groups()
        )

        buckets = self._create_buckets()

        roles = self._create_roles(
            buckets
        )

        instance_profiles = (
            self._create_instance_profiles(
                roles
            )
        )

        instances = self._create_instances(
            instance_profiles
        )

        return (
            instances,
            security_groups,
            buckets,
            roles,
            instance_profiles,
        )

    def _create_security_groups(
        self,
    ) -> list[SecurityGroup]:
        return [
            SecurityGroup(
                group_id="sg-cloudguard-web",
                group_name="cloudguard-web-sg",
                vpc_id="vpc-cloudguard-lab",
                inbound_rules=[
                    SecurityGroupRule(
                        protocol="tcp",
                        from_port=80,
                        to_port=80,
                        sources=[
                            "0.0.0.0/0"
                        ],
                    )
                ],
            )
        ]

    def _create_buckets(
        self,
    ) -> list[S3Bucket]:
        return [
            S3Bucket(
                name="customer-backups",
                region=self.REGION,
                public_access_block_enabled=True,
                policy_public=False,
                tags={
                    "Project": "CloudGuard",
                    "CloudGuardSensitive": "true",
                    "DataClassification": (
                        "confidential"
                    ),
                },
            )
        ]

    def _create_roles(
        self,
        buckets: list[S3Bucket],
    ) -> list[IAMRole]:
        bucket = buckets[0]

        bucket_arn = (
            f"arn:aws:s3:::{bucket.name}"
        )

        policy = IAMPolicy(
            name="CloudGuardS3ReadPolicy",
            arn=(
                "arn:aws:iam::"
                f"{self.ACCOUNT_ID}:policy/"
                "CloudGuardS3ReadPolicy"
            ),
            statements=[
                IAMPolicyStatement(
                    effect="Allow",
                    actions=[
                        "s3:ListBucket",
                    ],
                    resources=[
                        bucket_arn,
                    ],
                ),
                IAMPolicyStatement(
                    effect="Allow",
                    actions=[
                        "s3:GetObject",
                    ],
                    resources=[
                        f"{bucket_arn}/*",
                    ],
                ),
            ],
        )

        return [
            IAMRole(
                name="cloudguard-web-role",
                arn=(
                    "arn:aws:iam::"
                    f"{self.ACCOUNT_ID}:role/"
                    "cloudguard-web-role"
                ),
                role_id=(
                    "AROACLOUDGUARDLOCAL"
                ),
                attached_policies=[
                    policy
                ],
            )
        ]

    def _create_instance_profiles(
        self,
        roles: list[IAMRole],
    ) -> list[InstanceProfile]:
        role = roles[0]

        return [
            InstanceProfile(
                name=(
                    "cloudguard-web-profile"
                ),
                arn=(
                    "arn:aws:iam::"
                    f"{self.ACCOUNT_ID}:"
                    "instance-profile/"
                    "cloudguard-web-profile"
                ),
                role_names=[
                    role.name
                ],
            )
        ]

    def _create_instances(
        self,
        instance_profiles: list[
            InstanceProfile
        ],
    ) -> list[EC2Instance]:
        profile = instance_profiles[0]

        return [
            EC2Instance(
                instance_id=(
                    "i-cloudguard-web-01"
                ),
                instance_type="t3.micro",
                state="running",
                region=self.REGION,
                public_ip="203.0.113.10",
                private_ip="10.50.1.10",
                iam_instance_profile_arn=(
                    profile.arn
                ),
                security_group_ids=[
                    "sg-cloudguard-web"
                ],
            )
        ]
