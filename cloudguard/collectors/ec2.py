from pydantic import BaseModel, Field
from botocore.exceptions import ClientError

from cloudguard.collectors.aws_session import AWSSession


class EC2Instance(BaseModel):
    instance_id: str
    instance_type: str
    state: str
    region: str
    public_ip: str | None = None
    private_ip: str | None = None
    iam_role_arn: str | None = None
    security_group_ids: list[str] = Field(default_factory=list)


class SecurityGroupRule(BaseModel):
    protocol: str
    from_port: int | None = None
    to_port: int | None = None
    sources: list[str] = Field(default_factory=list)


class SecurityGroup(BaseModel):
    group_id: str
    group_name: str
    vpc_id: str | None = None
    inbound_rules: list[SecurityGroupRule] = Field(default_factory=list)


class EC2Collector:
    def __init__(self, aws_session: AWSSession) -> None:
        self.aws_session = aws_session
        self.client = aws_session.client("ec2")

    def collect_instances(self) -> list[EC2Instance]:
        instances: list[EC2Instance] = []

        paginator = self.client.get_paginator("describe_instances")

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    profile = instance.get("IamInstanceProfile")

                    instances.append(
                        EC2Instance(
                            instance_id=instance["InstanceId"],
                            instance_type=instance["InstanceType"],
                            state=instance["State"]["Name"],
                            region=self.aws_session.region or "unknown",
                            public_ip=instance.get("PublicIpAddress"),
                            private_ip=instance.get("PrivateIpAddress"),
                            iam_role_arn=(
                                profile.get("Arn")
                                if profile
                                else None
                            ),
                            security_group_ids=[
                                group["GroupId"]
                                for group in instance.get(
                                    "SecurityGroups", []
                                )
                            ],
                        )
                    )

        return instances

    def collect_security_groups(self) -> list[SecurityGroup]:
        groups: list[SecurityGroup] = []

        paginator = self.client.get_paginator(
            "describe_security_groups"
        )

        for page in paginator.paginate():
            for group in page.get("SecurityGroups", []):
                rules: list[SecurityGroupRule] = []

                for permission in group.get("IpPermissions", []):
                    sources = [
                        item["CidrIp"]
                        for item in permission.get("IpRanges", [])
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
                                "IpProtocol", "-1"
                            ),
                            from_port=permission.get("FromPort"),
                            to_port=permission.get("ToPort"),
                            sources=sources,
                        )
                    )

                groups.append(
                    SecurityGroup(
                        group_id=group["GroupId"],
                        group_name=group["GroupName"],
                        vpc_id=group.get("VpcId"),
                        inbound_rules=rules,
                    )
                )

        return groups
