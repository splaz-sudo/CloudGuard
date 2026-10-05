"""
Networking collectors for CloudGuard.

Collects VPC, Subnets, Route Tables, Internet Gateways,
NAT Gateways, Network ACLs, ENIs, Elastic IPs,
Load Balancers, and Target Groups.
"""

from dataclasses import dataclass, field
from pydantic import BaseModel, Field
from typing import Optional

from cloudguard.collectors.aws_session import AWSSession
from cloudguard.retry import RetryConfig, retry_with_backoff
from cloudguard.aws_errors import CollectorResult, classify_collector_error, safe_error_message


# --- Data Models ---

@dataclass
class VPC:
    vpc_id: str
    cidr_block: str
    state: str
    is_default: bool = False
    tags: dict[str, str] = field(default_factory=dict)
    region: str = ""


@dataclass
class Subnet:
    subnet_id: str
    vpc_id: str
    cidr_block: str
    availability_zone: str
    state: str
    map_public_ip_on_launch: bool = False
    tags: dict[str, str] = field(default_factory=dict)
    region: str = ""


@dataclass
class RouteTable:
    route_table_id: str
    vpc_id: str
    routes: list[dict] = field(default_factory=list)
    associations: list[dict] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    region: str = ""


@dataclass
class InternetGateway:
    igw_id: str
    state: str
    attachments: list[dict] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    region: str = ""


@dataclass
class NatGateway:
    nat_id: str
    vpc_id: str
    subnet_id: str
    state: str
    connectivity_type: str = "public"
    tags: dict[str, str] = field(default_factory=dict)
    region: str = ""


@dataclass
class NetworkAcl:
    acl_id: str
    vpc_id: str
    entries: list[dict] = field(default_factory=list)
    is_default: bool = False
    tags: dict[str, str] = field(default_factory=dict)
    region: str = ""


@dataclass
class NetworkInterface:
    eni_id: str
    vpc_id: str
    subnet_id: str
    availability_zone: str
    status: str
    private_ip: str = ""
    public_ip: str = ""
    security_groups: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    region: str = ""


@dataclass
class ElasticIp:
    allocation_id: str
    public_ip: str
    domain: str = "vpc"
    instance_id: str = ""
    network_interface_id: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    region: str = ""


@dataclass
class LoadBalancer:
    arn: str
    name: str
    type: str  # application | network | gateway
    scheme: str  # internet-facing | internal
    vpc_id: str
    state: dict = field(default_factory=dict)
    availability_zones: list[dict] = field(default_factory=list)
    security_groups: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    region: str = ""


@dataclass
class TargetGroup:
    arn: str
    name: str
    protocol: str
    port: int
    vpc_id: str
    target_type: str  # instance | ip | lambda
    targets: list[dict] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    region: str = ""


# --- Collector Classes ---

class VPCCollector:
    def __init__(
        self,
        aws_session: AWSSession,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.aws_session = aws_session
        self.client = aws_session.client("ec2")
        self.retry_config = retry_config or RetryConfig.standard()

    def collect_vpcs(self) -> CollectorResult:
        def _collect() -> list[VPC]:
            vpcs: list[VPC] = []
            paginator = self.client.get_paginator("describe_vpcs")
            for page in paginator.paginate():
                for vpc in page.get("Vpcs", []):
                    tags = {t["Key"]: t["Value"] for t in vpc.get("Tags", [])}
                    vpcs.append(
                        VPC(
                            vpc_id=vpc["VpcId"],
                            cidr_block=vpc.get("CidrBlock", ""),
                            state=vpc.get("State", ""),
                            is_default=vpc.get("IsDefault", False),
                            tags=tags,
                            region=self.aws_session.region or "",
                        )
                    )
            return vpcs

        return self._execute("vpc", "ec2", _collect)

    def _execute(self, collector, service, fn):
        return self._execute_with_retry(collector, service, None, fn)

    def _execute_with_retry(self, collector, service, region, fn):
        from cloudguard.aws_errors import classify_collector_error, safe_error_message
        import time
        started = time.perf_counter()
        try:
            data = retry_with_backoff(fn, self.retry_config)
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="success",
                resources_discovered=len(data),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                data=data,
            )
        except Exception as error:
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="failed",
                error_category=classify_collector_error(error),
                error_message=safe_error_message(error),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )


class SubnetCollector:
    def __init__(
        self,
        aws_session: AWSSession,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.aws_session = aws_session
        self.client = aws_session.client("ec2")
        self.retry_config = retry_config or RetryConfig.standard()

    def collect_subnets(self) -> CollectorResult:
        def _collect() -> list[Subnet]:
            subnets: list[Subnet] = []
            paginator = self.client.get_paginator("describe_subnets")
            for page in paginator.paginate():
                for subnet in page.get("Subnets", []):
                    tags = {t["Key"]: t["Value"] for t in subnet.get("Tags", [])}
                    subnets.append(
                        Subnet(
                            subnet_id=subnet["SubnetId"],
                            vpc_id=subnet.get("VpcId", ""),
                            cidr_block=subnet.get("CidrBlock", ""),
                            availability_zone=subnet.get("AvailabilityZone", ""),
                            state=subnet.get("State", ""),
                            map_public_ip_on_launch=subnet.get("MapPublicIpOnLaunch", False),
                            tags=tags,
                            region=self.aws_session.region or "",
                        )
                    )
            return subnets

        return self._execute_with_retry("subnet", "ec2", self.aws_session.region, _collect)

    def _execute_with_retry(self, collector, service, region, fn):
        from cloudguard.aws_errors import classify_collector_error, safe_error_message
        from cloudguard.retry import retry_with_backoff
        import time
        started = time.perf_counter()
        try:
            data = retry_with_backoff(fn, self.retry_config)
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="success",
                resources_discovered=len(data),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                data=data,
            )
        except Exception as error:
            from cloudguard.aws_errors import classify_collector_error, safe_error_message
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="failed",
                error_category=classify_collector_error(error),
                error_message=safe_error_message(error),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )


class RouteTableCollector:
    def __init__(
        self,
        aws_session: AWSSession,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.aws_session = aws_session
        self.client = aws_session.client("ec2")
        self.retry_config = retry_config or RetryConfig.standard()

    def collect_route_tables(self) -> CollectorResult:
        def _collect() -> list[RouteTable]:
            tables: list[RouteTable] = []
            paginator = self.client.get_paginator("describe_route_tables")
            for page in paginator.paginate():
                for rt in page.get("RouteTables", []):
                    tags = {t["Key"]: t["Value"] for t in rt.get("Tags", [])}
                    routes = []
                    for route in rt.get("Routes", []):
                        routes.append({
                            "destination": route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock") or route.get("DestinationPrefixListId") or "",
                            "gateway_id": route.get("GatewayId", ""),
                            "nat_gateway_id": route.get("NatGatewayId", ""),
                            "instance_id": route.get("InstanceId", ""),
                            "vpc_peering_connection_id": route.get("VpcPeeringConnectionId", ""),
                            "state": route.get("State", ""),
                        })
                    associations = []
                    for assoc in rt.get("Associations", []):
                        associations.append({
                            "association_id": assoc.get("RouteTableAssociationId", ""),
                            "subnet_id": assoc.get("SubnetId", ""),
                            "gateway_id": assoc.get("GatewayId", ""),
                            "main": assoc.get("Main", False),
                        })
                    tables.append(
                        RouteTable(
                            route_table_id=rt["RouteTableId"],
                            vpc_id=rt.get("VpcId", ""),
                            routes=routes,
                            associations=associations,
                            tags=tags,
                            region=self.aws_session.region or "",
                        )
                    )
            return tables

        return self._execute_with_retry("route_table", "ec2", self.aws_session.region, _collect)

    def _execute_with_retry(self, collector, service, region, fn):
        from cloudguard.aws_errors import classify_collector_error, safe_error_message
        from cloudguard.retry import retry_with_backoff
        import time
        started = time.perf_counter()
        try:
            data = retry_with_backoff(fn, self.retry_config)
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="success",
                resources_discovered=len(data),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                data=data,
            )
        except Exception as error:
            from cloudguard.aws_errors import classify_collector_error, safe_error_message
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="failed",
                error_category=classify_collector_error(error),
                error_message=safe_error_message(error),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )


class InternetGatewayCollector:
    def __init__(
        self,
        aws_session: AWSSession,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.aws_session = aws_session
        self.client = aws_session.client("ec2")
        self.retry_config = retry_config or RetryConfig.standard()

    def collect_internet_gateways(self) -> CollectorResult:
        def _collect() -> list[InternetGateway]:
            igws: list[InternetGateway] = []
            paginator = self.client.get_paginator("describe_internet_gateways")
            for page in paginator.paginate():
                for igw in page.get("InternetGateways", []):
                    tags = {t["Key"]: t["Value"] for t in igw.get("Tags", [])}
                    attachments = []
                    for att in igw.get("Attachments", []):
                        attachments.append({
                            "vpc_id": att.get("VpcId", ""),
                            "state": att.get("State", ""),
                        })
                    igws.append(
                        InternetGateway(
                            igw_id=igw["InternetGatewayId"],
                            state=igw.get("State", ""),
                            attachments=attachments,
                            tags=tags,
                            region=self.aws_session.region or "",
                        )
                    )
            return igws

        return self._execute_with_retry("internet_gateway", "ec2", self.aws_session.region, _collect)

    def _execute_with_retry(self, collector, service, region, fn):
        from cloudguard.aws_errors import classify_collector_error, safe_error_message
        from cloudguard.retry import retry_with_backoff
        import time
        started = time.perf_counter()
        try:
            data = retry_with_backoff(fn, self.retry_config)
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="success",
                resources_discovered=len(data),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                data=data,
            )
        except Exception as error:
            from cloudguard.aws_errors import classify_collector_error, safe_error_message
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="failed",
                error_category=classify_collector_error(error),
                error_message=safe_error_message(error),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )


class NatGatewayCollector:
    def __init__(
        self,
        aws_session: AWSSession,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.aws_session = aws_session
        self.client = aws_session.client("ec2")
        self.retry_config = retry_config or RetryConfig.standard()

    def collect_nat_gateways(self) -> CollectorResult:
        def _collect() -> list[NatGateway]:
            nats: list[NatGateway] = []
            paginator = self.client.get_paginator("describe_nat_gateways")
            for page in paginator.paginate():
                for nat in page.get("NatGateways", []):
                    tags = {t["Key"]: t["Value"] for t in nat.get("Tags", [])}
                    nats.append(
                        NatGateway(
                            nat_id=nat["NatGatewayId"],
                            vpc_id=nat.get("VpcId", ""),
                            subnet_id=nat.get("SubnetId", ""),
                            state=nat.get("State", ""),
                            connectivity_type=nat.get("ConnectivityType", "public"),
                            tags=tags,
                            region=self.aws_session.region or "",
                        )
                    )
            return nats

        return self._execute_with_retry("nat_gateway", "ec2", self.aws_session.region, _collect)

    def _execute_with_retry(self, collector, service, region, fn):
        from cloudguard.aws_errors import classify_collector_error, safe_error_message
        from cloudguard.retry import retry_with_backoff
        import time
        started = time.perf_counter()
        try:
            data = retry_with_backoff(fn, self.retry_config)
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="success",
                resources_discovered=len(data),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                data=data,
            )
        except Exception as error:
            from cloudguard.aws_errors import classify_collector_error, safe_error_message
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="failed",
                error_category=classify_collector_error(error),
                error_message=safe_error_message(error),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )


class NetworkAclCollector:
    def __init__(
        self,
        aws_session: AWSSession,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.aws_session = aws_session
        self.client = aws_session.client("ec2")
        self.retry_config = retry_config or RetryConfig.standard()

    def collect_network_acls(self) -> CollectorResult:
        def _collect() -> list[NetworkAcl]:
            acls: list[NetworkAcl] = []
            paginator = self.client.get_paginator("describe_network_acls")
            for page in paginator.paginate():
                for acl in page.get("NetworkAcls", []):
                    tags = {t["Key"]: t["Value"] for t in acl.get("Tags", [])}
                    entries = []
                    for entry in acl.get("Entries", []):
                        entries.append({
                            "rule_number": entry.get("RuleNumber", 0),
                            "protocol": entry.get("Protocol", "-1"),
                            "cidr_block": entry.get("CidrBlock", ""),
                            "ipv6_cidr_block": entry.get("Ipv6CidrBlock", ""),
                            "egress": entry.get("Egress", False),
                            "rule_action": entry.get("RuleAction", ""),
                        })
                    acls.append(
                        NetworkAcl(
                            acl_id=acl["NetworkAclId"],
                            vpc_id=acl.get("VpcId", ""),
                            entries=entries,
                            is_default=acl.get("IsDefault", False),
                            tags=tags,
                            region=self.aws_session.region or "",
                        )
                    )
            return acls

        return self._execute_with_retry("network_acl", "ec2", self.aws_session.region, _collect)

    def _execute_with_retry(self, collector, service, region, fn):
        from cloudguard.aws_errors import classify_collector_error, safe_error_message
        from cloudguard.retry import retry_with_backoff
        import time
        started = time.perf_counter()
        try:
            data = retry_with_backoff(fn, self.retry_config)
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="success",
                resources_discovered=len(data),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                data=data,
            )
        except Exception as error:
            from cloudguard.aws_errors import classify_collector_error, safe_error_message
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="failed",
                error_category=classify_collector_error(error),
                error_message=safe_error_message(error),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )


class NetworkInterfaceCollector:
    def __init__(
        self,
        aws_session: AWSSession,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.aws_session = aws_session
        self.client = aws_session.client("ec2")
        self.retry_config = retry_config or RetryConfig.standard()

    def collect_network_interfaces(self) -> CollectorResult:
        def _collect() -> list[NetworkInterface]:
            enis: list[NetworkInterface] = []
            paginator = self.client.get_paginator("describe_network_interfaces")
            for page in paginator.paginate():
                for eni in page.get("NetworkInterfaces", []):
                    tags = {t["Key"]: t["Value"] for t in eni.get("Tags", [])}
                    sgs = [sg["GroupId"] for sg in eni.get("Groups", [])]
                    enis.append(
                        NetworkInterface(
                            eni_id=eni["NetworkInterfaceId"],
                            vpc_id=eni.get("VpcId", ""),
                            subnet_id=eni.get("SubnetId", ""),
                            availability_zone=eni.get("AvailabilityZone", ""),
                            status=eni.get("Status", ""),
                            private_ip=eni.get("PrivateIpAddress", ""),
                            public_ip=eni.get("Association", {}).get("PublicIp", ""),
                            security_groups=sgs,
                            tags=tags,
                            region=self.aws_session.region or "",
                        )
                    )
            return enis

        return self._execute_with_retry("network_interface", "ec2", self.aws_session.region, _collect)

    def _execute_with_retry(self, collector, service, region, fn):
        from cloudguard.aws_errors import classify_collector_error, safe_error_message
        from cloudguard.retry import retry_with_backoff
        import time
        started = time.perf_counter()
        try:
            data = retry_with_backoff(fn, self.retry_config)
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="success",
                resources_discovered=len(data),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                data=data,
            )
        except Exception as error:
            from cloudguard.aws_errors import classify_collector_error, safe_error_message
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="failed",
                error_category=classify_collector_error(error),
                error_message=safe_error_message(error),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )


class ElasticIpCollector:
    def __init__(
        self,
        aws_session: AWSSession,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.aws_session = aws_session
        self.client = aws_session.client("ec2")
        self.retry_config = retry_config or RetryConfig.standard()

    def collect_elastic_ips(self) -> CollectorResult:
        def _collect() -> list[ElasticIp]:
            eips: list[ElasticIp] = []
            paginator = self.client.get_paginator("describe_addresses")
            for page in paginator.paginate():
                for addr in page.get("Addresses", []):
                    tags = {t["Key"]: t["Value"] for t in addr.get("Tags", [])}
                    eips.append(
                        ElasticIp(
                            allocation_id=addr.get("AllocationId", ""),
                            public_ip=addr.get("PublicIp", ""),
                            domain=addr.get("Domain", "vpc"),
                            instance_id=addr.get("InstanceId", ""),
                            network_interface_id=addr.get("NetworkInterfaceId", ""),
                            tags=tags,
                            region=self.aws_session.region or "",
                        )
                    )
            return eips

        return self._execute_with_retry("elastic_ip", "ec2", self.aws_session.region, _collect)

    def _execute_with_retry(self, collector, service, region, fn):
        from cloudguard.aws_errors import classify_collector_error, safe_error_message
        from cloudguard.retry import retry_with_backoff
        import time
        started = time.perf_counter()
        try:
            data = retry_with_backoff(fn, self.retry_config)
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="success",
                resources_discovered=len(data),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                data=data,
            )
        except Exception as error:
            from cloudguard.aws_errors import classify_collector_error, safe_error_message
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="failed",
                error_category=classify_collector_error(error),
                error_message=safe_error_message(error),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )


class LoadBalancerCollector:
    def __init__(
        self,
        aws_session: AWSSession,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.aws_session = aws_session
        self.client = aws_session.client("elbv2")
        self.retry_config = retry_config or RetryConfig.standard()

    def collect_load_balancers(self) -> CollectorResult:
        def _collect() -> list[LoadBalancer]:
            lbs: list[LoadBalancer] = []
            paginator = self.client.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    tags = {t["Key"]: t["Value"] for t in lb.get("Tags", [])}
                    azs = []
                    for az in lb.get("AvailabilityZones", []):
                        azs.append({
                            "zone_name": az.get("ZoneName", ""),
                            "subnet_id": az.get("SubnetId", ""),
                        })
                    lbs.append(
                        LoadBalancer(
                            arn=lb["LoadBalancerArn"],
                            name=lb["LoadBalancerName"],
                            type=lb.get("Type", ""),
                            scheme=lb.get("Scheme", ""),
                            vpc_id=lb.get("VpcId", ""),
                            state=lb.get("State", {}),
                            availability_zones=azs,
                            security_groups=lb.get("SecurityGroups", []),
                            tags=tags,
                            region=self.aws_session.region or "",
                        )
                    )
            return lbs

        return self._execute_with_retry("load_balancer", "elbv2", self.aws_session.region, _collect)

    def _execute_with_retry(self, collector, service, region, fn):
        from cloudguard.aws_errors import classify_collector_error, safe_error_message
        from cloudguard.retry import retry_with_backoff
        import time
        started = time.perf_counter()
        try:
            data = retry_with_backoff(fn, self.retry_config)
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="success",
                resources_discovered=len(data),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                data=data,
            )
        except Exception as error:
            from cloudguard.aws_errors import classify_collector_error, safe_error_message
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="failed",
                error_category=classify_collector_error(error),
                error_message=safe_error_message(error),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )


class TargetGroupCollector:
    def __init__(
        self,
        aws_session: AWSSession,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.aws_session = aws_session
        self.client = aws_session.client("elbv2")
        self.retry_config = retry_config or RetryConfig.standard()

    def collect_target_groups(self) -> CollectorResult:
        def _collect() -> list[TargetGroup]:
            tgs: list[TargetGroup] = []
            paginator = self.client.get_paginator("describe_target_groups")
            for page in paginator.paginate():
                for tg in page.get("TargetGroups", []):
                    tags = {t["Key"]: t["Value"] for t in tg.get("Tags", [])}
                    targets = []
                    # Note: describe_target_health would require separate calls per TG
                    tgs.append(
                        TargetGroup(
                            arn=tg["TargetGroupArn"],
                            name=tg["TargetGroupName"],
                            protocol=tg.get("Protocol", ""),
                            port=tg.get("Port", 0),
                            vpc_id=tg.get("VpcId", ""),
                            target_type=tg.get("TargetType", ""),
                            targets=targets,
                            tags=tags,
                            region=self.aws_session.region or "",
                        )
                    )
            return tgs

        return self._execute_with_retry("target_group", "elbv2", self.aws_session.region, _collect)

    def _execute_with_retry(self, collector, service, region, fn):
        from cloudguard.aws_errors import classify_collector_error, safe_error_message
        from cloudguard.retry import retry_with_backoff
        import time
        started = time.perf_counter()
        try:
            data = retry_with_backoff(fn, self.retry_config)
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="success",
                resources_discovered=len(data),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                data=data,
            )
        except Exception as error:
            from cloudguard.aws_errors import classify_collector_error, safe_error_message
            return CollectorResult(
                collector=collector,
                service=service,
                region=region,
                status="failed",
                error_category=classify_collector_error(error),
                error_message=safe_error_message(error),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )