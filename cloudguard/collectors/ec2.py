import time

from pydantic import BaseModel, Field

from cloudguard.aws_errors import CollectorResult
from cloudguard.collectors.aws_session import AWSSession
from cloudguard.retry import RetryConfig, retry_with_backoff


class EC2Instance(BaseModel):
    instance_id: str
    instance_type: str
    state: str
    region: str

    public_ip: str | None = None
    private_ip: str | None = None

    iam_instance_profile_arn: str | None = None

    security_group_ids: list[str] = Field(
        default_factory=list
    )


class SecurityGroupRule(BaseModel):
    protocol: str

    from_port: int | None = None
    to_port: int | None = None

    sources: list[str] = Field(
        default_factory=list
    )


class SecurityGroup(BaseModel):
    group_id: str
    group_name: str

    vpc_id: str | None = None

    inbound_rules: list[SecurityGroupRule] = Field(
        default_factory=list
    )


class EC2Collector:
    def __init__(
        self,
        aws_session: AWSSession,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.aws_session = aws_session
        self.client = aws_session.client("ec2")
        self.retry_config = retry_config or RetryConfig.standard()

    def collect_instances(
        self,
    ) -> CollectorResult:

        def _collect() -> list[EC2Instance]:
            instances: list[EC2Instance] = []

            paginator = self.client.get_paginator(
                "describe_instances"
            )

            for page in paginator.paginate():
                for reservation in page.get(
                    "Reservations", []
                ):
                    for instance in reservation.get(
                        "Instances", []
                    ):
                        profile = instance.get(
                            "IamInstanceProfile"
                        )

                        instances.append(
                            EC2Instance(
                                instance_id=(
                                    instance["InstanceId"]
                                ),
                                instance_type=(
                                    instance["InstanceType"]
                                ),
                                state=(
                                    instance["State"]["Name"]
                                ),
                                region=(
                                    self.aws_session.region
                                    or "unknown"
                                ),
                                public_ip=instance.get(
                                    "PublicIpAddress"
                                ),
                                private_ip=instance.get(
                                    "PrivateIpAddress"
                                ),
                                iam_instance_profile_arn=(
                                    profile.get("Arn")
                                    if profile
                                    else None
                                ),
                                security_group_ids=[
                                    group["GroupId"]
                                    for group in instance.get(
                                        "SecurityGroups",
                                        [],
                                    )
                                ],
                            )
                        )

            return instances

        started = time.perf_counter()

        try:
            instances = retry_with_backoff(_collect, self.retry_config)
            return CollectorResult(
                collector="ec2",
                service="ec2",
                region=self.aws_session.region,
                status="success",
                resources_discovered=len(instances),
                duration_ms=round(
                    (time.perf_counter() - started)
                    * 1000,
                    2,
                ),
                data=instances,
            )
        except Exception as error:
            from cloudguard.aws_errors import (
                classify_collector_error,
                safe_error_message,
            )
            return CollectorResult(
                collector="ec2",
                service="ec2",
                region=self.aws_session.region,
                status="failed",
                error_category=classify_collector_error(
                    error
                ),
                error_message=safe_error_message(error),
                duration_ms=round(
                    (time.perf_counter() - started)
                    * 1000,
                    2,
                ),
            )

    def collect_security_groups(
        self,
    ) -> CollectorResult:

        def _collect() -> list[SecurityGroup]:
            groups: list[SecurityGroup] = []

            paginator = self.client.get_paginator(
                "describe_security_groups"
            )

            for page in paginator.paginate():
                for group in page.get(
                    "SecurityGroups", []
                ):
                    rules: list[
                        SecurityGroupRule
                    ] = []

                    for permission in group.get(
                        "IpPermissions", []
                    ):
                        sources = [
                            item["CidrIp"]
                            for item in permission.get(
                                "IpRanges", []
                            )
                        ]

                        sources.extend(
                            item["CidrIpv6"]
                            for item in permission.get(
                                "Ipv6Ranges", []
                            )
                        )

                        rules.append(
                            SecurityGroupRule(
                                protocol=permission.get(
                                    "IpProtocol",
                                    "-1",
                                ),
                                from_port=permission.get(
                                    "FromPort"
                                ),
                                to_port=permission.get(
                                    "ToPort"
                                ),
                                sources=sources,
                            )
                        )

                    groups.append(
                        SecurityGroup(
                            group_id=group["GroupId"],
                            group_name=group[
                                "GroupName"
                            ],
                            vpc_id=group.get("VpcId"),
                            inbound_rules=rules,
                        )
                    )

            return groups

        started = time.perf_counter()

        try:
            groups = retry_with_backoff(_collect, self.retry_config)
            return CollectorResult(
                collector="ec2",
                service="ec2",
                region=self.aws_session.region,
                status="success",
                resources_discovered=len(groups),
                duration_ms=round(
                    (time.perf_counter() - started)
                    * 1000,
                    2,
                ),
                data=groups,
            )
        except Exception as error:
            from cloudguard.aws_errors import (
                classify_collector_error,
                safe_error_message,
            )
            return CollectorResult(
                collector="ec2",
                service="ec2",
                region=self.aws_session.region,
                status="failed",
                error_category=classify_collector_error(
                    error
                ),
                error_message=safe_error_message(error),
                duration_ms=round(
                    (time.perf_counter() - started)
                    * 1000,
                    2,
                ),
            )
