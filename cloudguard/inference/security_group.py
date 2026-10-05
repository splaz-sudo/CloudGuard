"""
Security Group Analysis 2.0

Deeper security group analysis with context-aware
findings. Detects patterns with evidence and
classifies findings based on context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from cloudguard.collectors.networking import SecurityGroup
from cloudguard.models.relationships import RelationshipType
from cloudguard.models.assets import CloudAsset, AssetType
from cloudguard.findings.fingerprints import network_exposure_fingerprint


class SGExposureType(str, Enum):
    """Types of security group exposure findings."""
    SSH_OPEN_TO_INTERNET = "ssh_open_to_internet"
    RDP_OPEN_TO_INTERNET = "rdp_open_to_internet"
    DATABASE_OPEN_TO_INTERNET = "database_open_to_internet"
    ALL_PROTOCOLS_OPEN = "all_protocols_open"
    BROAD_PORT_RANGE = "broad_port_range"
    ALL_IPV6_OPEN = "all_ipv6_open"
    RISKY_PEER_SG = "risky_peer_sg"
    UNUSED_SG = "unused_sg"


@dataclass
class SGFinding:
    """A security group analysis finding with evidence."""
    finding_type: SGExposureType
    severity: str
    sg_id: str
    sg_name: str
    rule: dict
    evidence: str
    context: dict = field(default_factory=dict)
    fingerprint: str = ""

    def to_finding(self, instance_id: str = None) -> dict:
        """Convert to finding dict format."""
        severity_map = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
        }
        
        affected = [self.sg_id]
        if instance_id:
            affected.append(instance_id)
            
        return {
            "id": f"CG-SG-{self.sg_id}-{self.finding_type.value}",
            "title": self._title(),
            "description": self._description(),
            "severity": severity_map.get(self.severity.lower(), "MEDIUM"),
            "category": "network",
            "affected_assets": affected,
            "evidence": [self.evidence],
            "remediation": self._remediation(),
            "risk_score": self._risk_score(),
            "fingerprint": self.fingerprint or network_exposure_fingerprint(self.sg_id),
        }

    def _title(self) -> str:
        titles = {
            SGExposureType.SSH_OPEN_TO_INTERNET: "SSH Open to Internet",
            SGExposureType.RDP_OPEN_TO_INTERNET: "RDP Open to Internet",
            SGExposureType.DATABASE_OPEN_TO_INTERNET: "Database Port Open to Internet",
            SGExposureType.ALL_PROTOCOLS_OPEN: "All Protocols Open to Internet",
            SGExposureType.BROAD_PORT_RANGE: "Broad Port Range Open to Internet",
            SGExposureType.ALL_IPV6_OPEN: "All IPv6 Traffic Open to Internet",
            SGExposureType.RISKY_PEER_SG: "Risky Security Group Peer Reference",
            SGExposureType.UNUSED_SG: "Unused Security Group",
        }
        return titles.get(self.finding_type, "Security Group Issue")

    def _description(self) -> str:
        descriptions = {
            SGExposureType.SSH_OPEN_TO_INTERNET: (
                "Security group allows SSH (port 22) from the Internet. "
                "This exposes the instance to brute-force attacks."
            ),
            SGExposureType.RDP_OPEN_TO_INTERNET: (
                "Security group allows RDP (port 3389) from the Internet. "
                "This exposes the instance to brute-force attacks and credential theft."
            ),
            SGExposureType.DATABASE_OPEN_TO_INTERNET: (
                "Security group allows database port (e.g., 3306, 5432) from the Internet. "
                "This exposes the database to unauthorized access and data exfiltration."
            ),
            SGExposureType.ALL_PROTOCOLS_OPEN: (
                "Security group allows all protocols from the Internet. "
                "This is equivalent to having no firewall protection."
            ),
            SGExposureType.BROAD_PORT_RANGE: (
                "Security group allows a broad port range (>100 ports) from the Internet. "
                "This increases the attack surface significantly."
            ),
            SGExposureType.ALL_IPV6_OPEN: (
                "Security group allows all IPv6 traffic from the Internet. "
                "IPv6 exposure is often overlooked but equally dangerous."
            ),
            SGExposureType.RISKY_PEER_SG: (
                "Security group references another security group that has "
                "Internet exposure, creating an indirect exposure path."
            ),
            SGExposureType.UNUSED_SG: (
                "Security group is not associated with any resources. "
                "Unused security groups increase management complexity and risk."
            ),
        }
        return descriptions.get(self.finding_type, "Security group configuration issue")

    def _remediation(self) -> str:
        remediations = {
            SGExposureType.SSH_OPEN_TO_INTERNET: (
                "Restrict SSH access to specific trusted IP ranges or use a bastion host/VPN."
            ),
            SGExposureType.RDP_OPEN_TO_INTERNET: (
                "Restrict RDP access to specific trusted IP ranges or use a bastion host/VPN."
            ),
            SGExposureType.DATABASE_OPEN_TO_INTERNET: (
                "Restrict database access to application subnets only. "
                "Use security group references instead of CIDR ranges."
            ),
            SGExposureType.ALL_PROTOCOLS_OPEN: (
                "Replace 'all protocols' (-1) with specific required protocols and ports."
            ),
            SGExposureType.BROAD_PORT_RANGE: (
                "Narrow port ranges to only the specific ports required by the application."
            ),
            SGExposureType.ALL_IPV6_OPEN: (
                "Restrict IPv6 ingress to specific required ranges and protocols."
            ),
            SGExposureType.RISKY_PEER_SG: (
                "Review the referenced security group's rules. "
                "Prefer direct CIDR references over security group references for ingress."
            ),
            SGExposureType.UNUSED_SG: (
                "Delete the security group if not needed, or associate it with resources."
            ),
        }
        return remediations.get(self.finding_type, "Review and restrict the security group rule.")


class SecurityGroupAnalyzer:
    """
    Context-aware security group analysis.

    Analyzes security groups with awareness of:
    - Effective Internet exposure (via NetworkExposureEngine2)
    - Resource sensitivity
    - Attack path participation
    - Peer SG references
    """

    SENSITIVE_PORTS = {
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "SQL Server",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch",
    }

    def __init__(
        self,
        exposure_evidence: dict[str, "ExposureEvidence"] | None = None,
    ):
        self.exposure_evidence = exposure_evidence or {}

    def analyze(
        self,
        security_groups: list["SecurityGroup"],
        instances: list = None,
        exposure_evidence: dict = None,
    ) -> list[SGFinding]:
        """
        Analyze security groups and return findings.

        Args:
            security_groups: List of SecurityGroup objects
            instances: List of EC2Instance objects (optional)
            exposure_evidence: Dict mapping asset_id -> ExposureEvidence (optional)

        Returns:
            List of SGFinding objects
        """
        self.exposure_evidence = exposure_evidence or {}
        findings: list[SGFinding] = []

        # Build instance -> SG mapping
        instance_sgs = {}
        if instances:
            for instance in instances:
                instance_sgs[instance.instance_id] = instance.security_group_ids

        # Track which SGs are used
        used_sgs = set()
        for sgs in instance_sgs.values():
            used_sgs.update(sgs)

        for sg in security_groups:
            findings = self._analyze_sg(sg, used_sgs, security_groups)
            findings.extend(self._analyze_peer_references(sg, security_groups))
            findings.extend(self._analyze_unused_sg(sg, used_sgs))
            findings = [f for f in findings if f]

            # Add context to each finding
            for finding in findings:
                finding.context = self._build_context(sg, finding)

            findings.extend(findings)

        return findings

    def _analyze_sg(
        self,
        sg: "SecurityGroup",
        used_sgs: set,
        all_sgs: list,
    ) -> list[SGFinding]:
        """Analyze a single security group for exposure findings."""
        findings = []

        for rule in sg.inbound_rules:
            # Check for Internet exposure
            has_internet = any(
                src in {"0.0.0.0/0", "::/0"}
                for src in rule.sources
            )

            if not has_internet:
                continue

            # Check rule severity
            finding = self._classify_rule(sg, rule)
            if finding:
                findings.append(finding)

        return findings

    def _classify_rule(self, sg: "SecurityGroup", rule: dict) -> "SGFinding | None":
        """Classify an Internet-facing rule."""
        protocol = rule.get("protocol", "")
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        sources = rule.get("sources", [])

        # All protocols open
        if protocol == "-1" or protocol == "all":
            return SGFinding(
                finding_type=SGExposureType.ALL_PROTOCOLS_OPEN,
                severity="critical",
                sg_id=sg.group_id,
                sg_name=sg.group_name,
                rule=rule,
                evidence=(
                    f"Security group {sg.group_id} ({sg.group_name}) "
                    f"allows all protocols from {', '.join(sources)}"
                ),
            )

        # Check port ranges
        if from_port is not None and to_port is not None:
            port_range = to_port - from_port
            if port_range >= 100:
                return SGFinding(
                    finding_type=SGExposureType.BROAD_PORT_RANGE,
                    severity="high",
                    sg_id=sg.group_id,
                    sg_name=sg.group_name,
                    rule=rule,
                    evidence=(
                        f"Security group {sg.group_id} ({sg.group_name}) "
                        f"allows broad port range {from_port}-{to_port} "
                        f"from {', '.join(sources)}"
                    ),
                )

            # Check sensitive ports
            for port, name in self.SENSITIVE_PORTS.items():
                if from_port <= port <= to_port:
                    if name in ("SSH", "Telnet"):
                        finding_type = SGExposureType.SSH_OPEN_TO_INTERNET
                        severity = "critical"
                    elif name == "RDP":
                        finding_type = SGExposureType.RDP_OPEN_TO_INTERNET
                        severity = "critical"
                    else:
                        finding_type = SGExposureType.DATABASE_OPEN_TO_INTERNET
                        severity = "critical"

                    return SGFinding(
                        finding_type=finding_type,
                        severity=severity,
                        sg_id=sg.group_id,
                        sg_name=sg.group_name,
                        rule=rule,
                        evidence=(
                            f"Security group {sg.group_id} ({sg.group_name}) "
                            f"allows {name} (port {port}) from {', '.join(sources)}"
                        ),
                    )

        # Check for IPv6 all-open
        if "::/0" in sources and protocol == "-1":
            return SGFinding(
                finding_type=SGExposureType.ALL_IPV6_OPEN,
                severity="high",
                sg_id=sg.group_id,
                sg_name=sg.group_name,
                rule=rule,
                evidence=(
                    f"Security group {sg.group_id} ({sg.group_name}) "
                    f"allows all IPv6 traffic from ::/0"
                ),
            )

        return None

    def _analyze_peer_references(
        self,
        sg: "SecurityGroup",
        all_sgs: list,
    ) -> list["SGFinding"]:
        """Check for risky peer SG references."""
        findings = []

        sg_by_id = {sg.group_id: sg for sg in all_sgs}

        for rule in sg.inbound_rules:
            for source in rule.sources:
                # Check if source is a security group reference
                if source.startswith("sg-"):
                    peer_sg = sg_by_id.get(source)
                    if peer_sg:
                        # Check if peer has Internet exposure
                        peer_exposed = self._sg_has_internet_exposure(peer_sg, all_sgs)
                        if peer_exposed:
                            findings.append(SGFinding(
                                finding_type=SGExposureType.RISKY_PEER_SG,
                                severity="high",
                                sg_id=sg.group_id,
                                sg_name=sg.group_name,
                                rule={"peer_sg": source, "original_rule": rule.__dict__ if hasattr(rule, '__dict__') else str(rule)},
                                evidence=(
                                    f"Security group {sg.group_id} ({sg.group_name}) "
                                    f"references peer SG {source} ({peer_sg.group_name}) "
                                    f"which has Internet exposure, creating indirect exposure"
                                ),
                            ))

        return findings

    def _sg_has_internet_exposure(self, sg: "SecurityGroup", all_sgs: list) -> bool:
        """Recursively check if an SG has Internet exposure."""
        for rule in sg.inbound_rules:
            if any(src in {"0.0.0.0/0", "::/0"} for src in rule.sources):
                return True
            for source in rule.sources:
                if source.startswith("sg-"):
                    peer_sg = next((s for s in all_sgs if s.group_id == source), None)
                    if peer_sg and self._sg_has_internet_exposure(peer_sg, all_sgs):
                        return True
        return False

    def _analyze_unused_sg(
        self,
        sg: "SecurityGroup",
        used_sgs: set,
    ) -> list[SGFinding]:
        """Check for unused security groups."""
        if sg.group_id not in used_sgs:
            return [SGFinding(
                finding_type=SGExposureType.UNUSED_SG,
                severity="low",
                sg_id=sg.group_id,
                sg_name=sg.group_name,
                rule={},
                evidence=(
                    f"Security group {sg.group_id} ({sg.group_name}) "
                    f"is not associated with any resources"
                ),
            )]
        return []

    def _build_context(self, sg: "SecurityGroup", finding: "SGFinding") -> dict:
        """Build context for a finding."""
        return {
            "security_group_id": sg.group_id,
            "security_group_name": sg.group_name,
            "vpc_id": sg.vpc_id,
            "finding_type": finding.finding_type.value,
            "severity": finding.severity,
        }