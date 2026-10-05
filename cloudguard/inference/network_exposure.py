"""
Network Exposure Engine 2.0

Effective reachability analysis that considers the full
network path from Internet to a resource, not just
security group rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from cloudguard.models.assets import CloudAsset, AssetType
from cloudguard.collectors.networking import (
    VPC, Subnet, RouteTable, InternetGateway,
    NatGateway, NetworkAcl, NetworkInterface,
    ElasticIp, LoadBalancer, TargetGroup,
)
from cloudguard.models.relationships import (
    Relationship,
    RelationshipType,
)


class ExposureType(str, Enum):
    DIRECT_INTERNET_EXPOSURE = "direct_internet_exposure"
    LOAD_BALANCER_EXPOSURE = "load_balancer_exposure"
    PRIVATE = "private"
    UNKNOWN = "unknown"


@dataclass
class ExposureEvidence:
    """Structured evidence for exposure determination."""
    exposure_type: ExposureType
    resource_id: str
    resource_type: AssetType
    public_ip: Optional[str] = None
    eni_id: Optional[str] = None
    subnet_id: Optional[str] = None
    vpc_id: Optional[str] = None
    igw_id: Optional[str] = None
    nat_id: Optional[str] = None
    route_table_id: Optional[str] = None
    route_destination: Optional[str] = None
    igw_id_on_route: Optional[str] = None
    sg_id: Optional[str] = None
    sg_rule: Optional[str] = None
    nacl_id: Optional[str] = None
    nacl_allows: bool = True
    lb_arn: Optional[str] = None
    lb_type: Optional[str] = None
    lb_scheme: Optional[str] = None
    tg_arn: Optional[str] = None
    tg_protocol: Optional[str] = None
    tg_port: Optional[int] = None
    protocol: Optional[str] = None
    port_range: Optional[str] = None
    details: str = ""


class NetworkExposureEngine2:
    """
    Effective network exposure analysis.

    Determines exposure by evaluating the complete
    network path: Internet -> IGW -> Route Table ->
    Subnet -> NACL -> SG -> Resource.

    Unlike the simple SG-only analyzer, this engine
    requires a complete path to exist.
    """

    INTERNET_CIDRS = {"0.0.0.0/0", "::/0"}

    def __init__(
        self,
        vpcs: list,
        subnets: list,
        route_tables: list,
        internet_gateways: list,
        nat_gateways: list,
        network_acls: list,
        network_interfaces: list,
        elastic_ips: list,
        load_balancers: list,
        target_groups: list,
        security_groups: list,
        instances: list,
    ):
        self.vpcs = {v.vpc_id: v for v in vpcs}
        self.subnets = {s.subnet_id: s for s in subnets}
        self.route_tables = {rt.route_table_id: rt for rt in route_tables}
        self.internet_gateways = {igw.igw_id: igw for igw in internet_gateways}
        self.nat_gateways = {nat.nat_id: nat for nat in nat_gateways}
        self.network_acls = {acl.acl_id: acl for acl in network_acls}
        self.network_interfaces = {eni.eni_id: eni for eni in network_interfaces}
        self.elastic_ips = {eip.allocation_id: eip for eip in elastic_ips}
        self.load_balancers = {lb.arn: lb for lb in load_balancers}
        self.target_groups = {tg.arn: tg for tg in target_groups}
        self.security_groups = {sg.group_id: sg for sg in security_groups}
        self.instances = {i.instance_id: i for i in instances}

        # Build subnet -> route table mapping
        self._subnet_to_rt = {}
        for rt in route_tables:
            for assoc in rt.associations:
                if assoc.get("subnet_id"):
                    self._subnet_to_rt[assoc["subnet_id"]] = rt

        # Build subnet -> NACL mapping
        self._subnet_to_nacl = {}
        for nacl in network_acls:
            # NACLs are associated at subnet level in AWS
            # We'll need to track this properly
            pass

    def analyze_exposure(
        self,
        asset: CloudAsset,
    ) -> ExposureEvidence:
        """
        Analyze effective exposure for a single asset.

        Returns ExposureEvidence with the determined
        exposure type and supporting evidence.
        """
        if asset.asset_type == AssetType.EC2:
            return self._analyze_ec2_exposure(asset)
        elif asset.asset_type == AssetType.LOAD_BALANCER:
            return self._analyze_lb_exposure(asset)
        elif asset.asset_type == AssetType.RDS:
            return self._analyze_rds_exposure(asset)
        elif asset.asset_type in (AssetType.LAMBDA, AssetType.SECRET):
            return self._analyze_managed_exposure(asset)

        return ExposureEvidence(
            exposure_type=ExposureType.UNKNOWN,
            resource_id=asset.id,
            resource_type=asset.asset_type,
            details="Unsupported asset type for exposure analysis",
        )

    def _analyze_ec2_exposure(self, asset: CloudAsset) -> ExposureEvidence:
        """Analyze EC2 instance exposure through full network path."""
        # Find instance
        instance = self.instances.get(asset.id)
        if not instance:
            return ExposureEvidence(
                exposure_type=ExposureType.UNKNOWN,
                resource_id=asset.id,
                resource_type=asset.asset_type,
                details="Instance not found in collector data",
            )

        # Get ENIs for this instance
        enis = [
            eni for eni in self.network_interfaces.values()
            if instance.instance_id in (eni.eni_id or "")
        ]

        if not enis:
            return ExposureEvidence(
                exposure_type=ExposureType.PRIVATE,
                resource_id=asset.id,
                resource_type=asset.asset_type,
                details="No network interfaces found for instance",
            )

        # Check each ENI for exposure
        for eni in enis:
            evidence = self._analyze_eni_exposure(eni, asset.id)
            if evidence.exposure_type != ExposureType.PRIVATE:
                return evidence

        return ExposureEvidence(
            exposure_type=ExposureType.PRIVATE,
            resource_id=asset.id,
            resource_type=asset.asset_type,
            details="No ENI found with complete Internet path",
        )

    def _analyze_eni_exposure(
        self,
        eni,
        instance_id: str,
    ) -> ExposureEvidence:
        """
        Analyze exposure for a single ENI by tracing
        the complete network path.
        """
        # 1. Check if ENI has public IP (direct or EIP)
        public_ip = eni.public_ip
        eip_association = None

        if not public_ip:
            # Check for associated EIP
            for eip in self.elastic_ips.values():
                if eip.network_interface_id == eni.eni_id:
                    public_ip = eip.public_ip
                    break

        if not public_ip:
            return ExposureEvidence(
                exposure_type=ExposureType.PRIVATE,
                resource_id=eni.eni_id,
                resource_type=AssetType.NETWORK_INTERFACE,
                details="ENI has no public IP or Elastic IP",
            )

        # 2. Find subnet and VPC
        subnet = self.subnets.get(eni.subnet_id)
        if not subnet:
            return ExposureEvidence(
                exposure_type=ExposureType.UNKNOWN,
                resource_id=eni.eni_id,
                resource_type=AssetType.NETWORK_INTERFACE,
                details=f"Subnet {eni.subnet_id} not found",
            )

        vpc = self.vpcs.get(subnet.vpc_id)
        if not vpc:
            return ExposureEvidence(
                exposure_type=ExposureType.UNKNOWN,
                resource_id=eni.eni_id,
                resource_type=AssetType.NETWORK_INTERFACE,
                details=f"VPC {subnet.vpc_id} not found",
            )

        # 3. Find route table for subnet
        route_table = self._subnet_to_rt.get(subnet.subnet_id)
        if not route_table:
            return ExposureEvidence(
                exposure_type=ExposureType.PRIVATE,
                resource_id=eni.eni_id,
                resource_type=AssetType.NETWORK_INTERFACE,
                subnet_id=subnet.subnet_id,
                vpc_id=vpc.vpc_id,
                details="Subnet has no associated route table",
            )

        # 4. Check for route to IGW
        igw_route = None
        igw_id = None
        for route in route_table.routes:
            if route.get("destination") in ("0.0.0.0/0", "::/0"):
                igw_id = route.get("gateway_id")
                if igw_id and igw_id.startswith("igw-"):
                    igw_route = route
                    break

        if not igw_route:
            # Check for NAT gateway route (private subnet with NAT)
            nat_route = None
            for route in route_table.routes:
                if route.get("destination") in ("0.0.0.0/0", "::/0"):
                    nat_id = route.get("nat_gateway_id")
                    if nat_id and nat_id.startswith("nat-"):
                        nat_route = route
                        break

            if nat_route:
                # Has NAT gateway - check if ENI has public IP anyway (misconfiguration)
                return ExposureEvidence(
                    exposure_type=ExposureType.DIRECT_INTERNET_EXPOSURE,
                    resource_id=eni.eni_id,
                    resource_type=AssetType.NETWORK_INTERFACE,
                    public_ip=public_ip,
                    eni_id=eni.eni_id,
                    subnet_id=subnet.subnet_id,
                    vpc_id=vpc.vpc_id,
                    nat_id=nat_route.get("nat_gateway_id"),
                    details=(
                        f"ENI has public IP {public_ip} but subnet routes "
                        f"through NAT gateway {nat_route.get('nat_gateway_id')}. "
                        f"This may indicate a misconfiguration."
                    ),
                )

            return ExposureEvidence(
                exposure_type=ExposureType.PRIVATE,
                resource_id=eni.eni_id,
                resource_type=AssetType.NETWORK_INTERFACE,
                public_ip=public_ip,
                eni_id=eni.eni_id,
                subnet_id=subnet.subnet_id,
                vpc_id=vpc.vpc_id,
                route_table_id=route_table.route_table_id,
                details="Subnet has no route to Internet Gateway",
            )

        # 5. Check IGW is attached to VPC
        igw = self.internet_gateways.get(igw_id)
        if not igw:
            return ExposureEvidence(
                exposure_type=ExposureType.UNKNOWN,
                resource_id=eni.eni_id,
                resource_type=AssetType.NETWORK_INTERFACE,
                public_ip=public_ip,
                eni_id=eni.eni_id,
                subnet_id=subnet.subnet_id,
                vpc_id=vpc.vpc_id,
                route_table_id=route_table.route_table_id,
                igw_id=igw_id,
                route_destination="0.0.0.0/0",
                igw_id_on_route=igw_id,
                details=f"Route references IGW {igw_id} but IGW not found",
            )

        # Check IGW is attached to this VPC
        igw_attached = False
        for att in igw.attachments:
            if att.get("vpc_id") == vpc.vpc_id:
                igw_attached = True
                break

        if not igw_attached:
            return ExposureEvidence(
                exposure_type=ExposureType.PRIVATE,
                resource_id=eni.eni_id,
                resource_type=AssetType.NETWORK_INTERFACE,
                public_ip=public_ip,
                eni_id=eni.eni_id,
                subnet_id=subnet.subnet_id,
                vpc_id=vpc.vpc_id,
                route_table_id=route_table.route_table_id,
                igw_id=igw_id,
                route_destination="0.0.0.0/0",
                igw_id_on_route=igw_id,
                details=f"IGW {igw_id} not attached to VPC {vpc.vpc_id}",
            )

        # 6. Check NACLs
        nacl_allows = self._check_nacl_allows(subnet.subnet_id)

        # 7. Check Security Groups
        sg_allows, sg_rule = self._check_sg_allows(eni.security_groups)

        if not sg_allows:
            return ExposureEvidence(
                exposure_type=ExposureType.PRIVATE,
                resource_id=eni.eni_id,
                resource_type=AssetType.NETWORK_INTERFACE,
                public_ip=public_ip,
                eni_id=eni.eni_id,
                subnet_id=subnet.subnet_id,
                vpc_id=vpc.vpc_id,
                route_table_id=route_table.route_table_id,
                igw_id=igw_id,
                route_destination="0.0.0.0/0",
                igw_id_on_route=igw_id,
                nacl_id=self._get_nacl_id(subnet.subnet_id),
                nacl_allows=nacl_allows,
                sg_id=eni.security_groups[0] if eni.security_groups else None,
                sg_rule="Security group blocks Internet ingress",
                protocol=None,
                port_range=None,
                details="Complete path exists but security group blocks ingress",
            )

        # Complete path exists!
        return ExposureEvidence(
            exposure_type=ExposureType.DIRECT_INTERNET_EXPOSURE,
            resource_id=eni.eni_id,
            resource_type=AssetType.NETWORK_INTERFACE,
            public_ip=public_ip,
            eni_id=eni.eni_id,
            subnet_id=subnet.subnet_id,
            vpc_id=vpc.vpc_id,
            route_table_id=route_table.route_table_id,
            igw_id=igw_id,
            route_destination="0.0.0.0/0",
            igw_id_on_route=igw_id,
            nacl_id=self._get_nacl_id(subnet.subnet_id),
            nacl_allows=nacl_allows,
            sg_id=eni.security_groups[0] if eni.security_groups else None,
            sg_rule=sg_rule,
            protocol=sg_rule.split(":")[0] if sg_rule and ":" in sg_rule else None,
            port_range=sg_rule.split(":")[1] if sg_rule and ":" in sg_rule else None,
            details=(
                f"Complete Internet path: Internet -> IGW {igw_id} -> "
                f"Route Table {route_table.route_table_id} -> "
                f"Subnet {subnet.subnet_id} -> "
                f"SG {eni.security_groups[0] if eni.security_groups else 'N/A'} -> "
                f"ENI {eni.eni_id} (public IP {public_ip})"
            ),
        )

    def _analyze_lb_exposure(self, asset: CloudAsset) -> ExposureEvidence:
        """Analyze Load Balancer exposure."""
        lb = self.load_balancers.get(asset.id)
        if not lb:
            return ExposureEvidence(
                exposure_type=ExposureType.UNKNOWN,
                resource_id=asset.id,
                resource_type=asset.asset_type,
                details="Load balancer not found in collector data",
            )

        if lb.scheme != "internet-facing":
            return ExposureEvidence(
                exposure_type=ExposureType.PRIVATE,
                resource_id=asset.id,
                resource_type=asset.asset_type,
                details=f"Load balancer scheme is {lb.scheme}, not internet-facing",
            )

        # Check if LB has listeners on sensitive ports
        # This would require additional API calls to describe_listeners
        return ExposureEvidence(
            exposure_type=ExposureType.LOAD_BALANCER_EXPOSURE,
            resource_id=asset.id,
            resource_type=asset.asset_type,
            lb_arn=lb.arn,
            lb_type=lb.type,
            lb_scheme=lb.scheme,
            vpc_id=lb.vpc_id,
            details=(
                f"Internet-facing {lb.type} load balancer {lb.name} "
                f"in VPC {lb.vpc_id}"
            ),
        )

    def _analyze_rds_exposure(self, asset: CloudAsset) -> ExposureEvidence:
        """RDS exposure would require subnet group analysis."""
        return ExposureEvidence(
            exposure_type=ExposureType.UNKNOWN,
            resource_id=asset.id,
            resource_type=asset.asset_type,
            details="RDS exposure analysis not yet implemented",
        )

    def _analyze_managed_exposure(self, asset: CloudAsset) -> ExposureEvidence:
        """Managed services (Lambda, Secrets) have no direct network exposure."""
        return ExposureEvidence(
            exposure_type=ExposureType.PRIVATE,
            resource_id=asset.id,
            resource_type=asset.asset_type,
            details=f"{asset.asset_type.value} is a managed service with no direct network exposure",
        )

    def _check_nacl_allows(self, subnet_id: str) -> bool:
        """Check if NACL allows inbound Internet traffic."""
        # NACL association is at subnet level
        # For now, assume allows (default NACL allows all)
        # A full implementation would check NetworkAcl.entries
        return True

    def _get_nacl_id(self, subnet_id: str) -> Optional[str]:
        # Would need to track subnet -> NACL mapping
        return None

    def _check_sg_allows(self, sg_ids: list[str]) -> tuple[bool, Optional[str]]:
        """Check if any security group allows Internet ingress."""
        for sg_id in sg_ids:
            sg = self.security_groups.get(sg_id)
            if not sg:
                continue
            for rule in sg.inbound_rules:
                if any(src in self.INTERNET_CIDRS for src in rule.sources):
                    rule_desc = f"{rule.protocol}:{rule.from_port}-{rule.to_port}"
                    return True, rule_desc
        return False, None

    def infer_relationships(self, assets: list[CloudAsset]) -> list[Relationship]:
        """
        Create exposure relationships for assets with
        effective Internet exposure.
        """
        relationships = []

        for asset in assets:
            evidence = self.analyze_exposure(asset)

            if evidence.exposure_type == ExposureType.DIRECT_INTERNET_EXPOSURE:
                relationships.append(
                    Relationship(
                        source="internet",
                        target=asset.id,
                        relationship_type=RelationshipType.EXPOSED_TO,
                        evidence=evidence.details,
                    )
                )
            elif evidence.exposure_type == ExposureType.LOAD_BALANCER_EXPOSURE:
                relationships.append(
                    Relationship(
                        source="internet",
                        target=asset.id,
                        relationship_type=RelationshipType.EXPOSED_TO,
                        evidence=evidence.details,
                    )
                )

        return relationships