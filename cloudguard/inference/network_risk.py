from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloudguard.findings.scoring import (
    severity_from_score,
)


@dataclass
class ExposedService:
    protocol: str
    from_port: int | None
    to_port: int | None
    sources: list[str]
    security_group_id: str
    security_group_name: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "from_port": self.from_port,
            "to_port": self.to_port,
            "sources": self.sources,
            "security_group_id": (
                self.security_group_id
            ),
            "security_group_name": (
                self.security_group_name
            ),
        }


@dataclass
class NetworkRisk:
    asset_id: str
    asset_name: str

    risk_score: int
    severity: str

    public_ip: str | None = None

    security_groups: list[str] = field(
        default_factory=list
    )

    exposed_services: list[
        ExposedService
    ] = field(
        default_factory=list
    )

    attached_identities: list[str] = field(
        default_factory=list
    )

    sensitive_resources: list[str] = field(
        default_factory=list
    )

    attack_paths: list[list[str]] = field(
        default_factory=list
    )

    risk_factors: list[str] = field(
        default_factory=list
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "public_ip": self.public_ip,
            "security_groups": sorted(
                set(self.security_groups)
            ),
            "exposed_services": [
                service.to_dict()
                for service in (
                    self.exposed_services
                )
            ],
            "attached_identities": sorted(
                set(self.attached_identities)
            ),
            "sensitive_resources": sorted(
                set(self.sensitive_resources)
            ),
            "attack_paths": (
                self.attack_paths
            ),
            "risk_factors": (
                self.risk_factors
            ),
            "metadata": self.metadata,
        }


def calculate_network_risk(
    *,
    asset_id: str,
    asset_name: str,
    public_ip: str | None,
    security_groups: list[str],
    exposed_services: list[ExposedService],
    attached_identities: list[str],
    sensitive_resources: list[str],
    attack_paths: list[list[str]],
    metadata: dict[str, Any] | None = None,
) -> NetworkRisk:
    """
    Calculates contextual network risk.

    The score is a CloudGuard correlation score.
    It is not an AWS-native risk score.
    """

    score = 0
    risk_factors: list[str] = []

    if public_ip:
        score += 15

        risk_factors.append(
            "Workload has a public IP address."
        )

    if exposed_services:
        score += 25

        risk_factors.append(
            "Security group rules permit "
            "internet-originated inbound traffic."
        )

    if _has_sensitive_exposure(
        exposed_services
    ):
        score += 20

        risk_factors.append(
            "Internet exposure includes a "
            "security-sensitive service or "
            "broad port range."
        )

    if attached_identities:
        score += 15

        risk_factors.append(
            "Internet-exposed workload is "
            "associated with an IAM identity."
        )

    if sensitive_resources:
        score += 15

        risk_factors.append(
            "The workload's reachable identity "
            "can access a sensitive resource."
        )

    if attack_paths:
        score += 10

        risk_factors.append(
            "Workload participates in a "
            "discovered attack path to a "
            "sensitive resource."
        )

    score = min(score, 100)

    return NetworkRisk(
        asset_id=asset_id,
        asset_name=asset_name,
        risk_score=score,
        severity=severity_from_score(score).lower(),
        public_ip=public_ip,
        security_groups=security_groups,
        exposed_services=exposed_services,
        attached_identities=attached_identities,
        sensitive_resources=sensitive_resources,
        attack_paths=attack_paths,
        risk_factors=risk_factors,
        metadata=metadata or {},
    )


def _has_sensitive_exposure(
    services: list[ExposedService],
) -> bool:
    sensitive_ports = {
        22,
        23,
        3389,
        3306,
        5432,
        6379,
        27017,
    }

    for service in services:
        from_port = service.from_port
        to_port = service.to_port

        if from_port is None:
            return True

        if to_port is None:
            return True

        if from_port == -1:
            return True

        if to_port == -1:
            return True

        if (
            to_port - from_port
            >= 100
        ):
            return True

        for port in sensitive_ports:
            if (
                from_port
                <= port
                <= to_port
            ):
                return True

    return False