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
from cloudguard.collectors.networking import (
    VPC,
    Subnet,
    RouteTable,
    InternetGateway,
    NatGateway,
    NetworkAcl,
    NetworkInterface,
    ElasticIp,
    LoadBalancer,
    TargetGroup,
    VPCCollector,
    SubnetCollector,
    RouteTableCollector,
    InternetGatewayCollector,
    NatGatewayCollector,
    NetworkAclCollector,
    NetworkInterfaceCollector,
    ElasticIpCollector,
    LoadBalancerCollector,
    TargetGroupCollector,
)


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
    vpcs: list[VPC] = field(
        default_factory=list
    )
    subnets: list[Subnet] = field(
        default_factory=list
    )
    route_tables: list[RouteTable] = field(
        default_factory=list
    )
    internet_gateways: list[InternetGateway] = field(
        default_factory=list
    )
    nat_gateways: list[NatGateway] = field(
        default_factory=list
    )
    network_acls: list[NetworkAcl] = field(
        default_factory=list
    )
    network_interfaces: list[NetworkInterface] = field(
        default_factory=list
    )
    elastic_ips: list[ElasticIp] = field(
        default_factory=list
    )
    load_balancers: list[LoadBalancer] = field(
        default_factory=list
    )
    target_groups: list[TargetGroup] = field(
        default_factory=list
    )
    account_id: str = ""
    regions: list[str] = field(
        default_factory=list
    )
