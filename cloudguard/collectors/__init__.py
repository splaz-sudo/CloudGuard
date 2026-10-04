from dataclasses import dataclass, field

from cloudguard.collectors.ec2 import (
    EC2Instance,
    SecurityGroup,
)
from cloudguard.collectors.iam import (
    IAMRole,
    IAMUser,
    InstanceProfile,
)
from cloudguard.collectors.s3 import S3Bucket


@dataclass
class CollectedEnvironment:
    """
    Raw read-only collector output for one
    environment. Stored alongside each scan so
    derived services (network/identity/report)
    can run against the exact scanned state.
    """

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
    users: list[IAMUser] = field(
        default_factory=list
    )
    instance_profiles: list[InstanceProfile] = (
        field(default_factory=list)
    )
    account_id: str = ""
    regions: list[str] = field(
        default_factory=list
    )
