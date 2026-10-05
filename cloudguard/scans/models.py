from dataclasses import dataclass, field as dc_field
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from cloudguard.aws_errors import CollectorResult
from cloudguard.collectors import (
    CollectedEnvironment,
)
from cloudguard.findings.models import Finding
from cloudguard.graph.attack_paths import AttackPath
from cloudguard.graph.security_graph import (
    SecurityGraph,
)
from cloudguard.models.assets import CloudAsset
from cloudguard.models.relationships import (
    Relationship,
)
from cloudguard.remediation.models import (
    Remediation,
)


class ScanSource(str, Enum):
    LOCAL_LAB = "local_lab"
    AWS = "aws"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class ScanRecord(BaseModel):
    """
    Metadata for one immutable CloudGuard scan.

    A scan is a point-in-time security
    snapshot. Completed scans are never
    mutated; a changed environment produces a
    new scan.
    """

    scan_id: str

    source: ScanSource
    environment: str

    status: ScanStatus = ScanStatus.PENDING

    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None

    account_identifier: str | None = None
    regions: list[str] = Field(
        default_factory=list
    )

    asset_count: int = 0
    relationship_count: int = 0
    finding_count: int = 0
    attack_path_count: int = 0
    highest_risk: int = 0

    failed_collectors: list[str] = Field(
        default_factory=list
    )

    error_message: str | None = None

    scanner_version: str = ""

    duration_ms: float | None = None


class ScanCreateRequest(BaseModel):
    source: ScanSource = ScanSource.LOCAL_LAB

    # Local lab scenario name, or an AWS
    # profile override for AWS scans.
    environment: str = ""

    regions: list[str] = Field(
        default_factory=list
    )

    # When true (default), the request blocks
    # until the scan finishes. Local lab scans
    # complete in milliseconds.
    wait: bool = True


@dataclass
class ScanSnapshot:
    """
    A scan's full immutable analysis state,
    reconstructed from persistence.

    The security graph is rebuilt from the
    stored assets and relationships so
    simulation can run against the exact
    scanned state without mutating it.
    """

    record: ScanRecord
    assets: list[CloudAsset] = dc_field(
        default_factory=list
    )
    relationships: list[Relationship] = (
        dc_field(default_factory=list)
    )
    findings: list[Finding] = dc_field(
        default_factory=list
    )
    attack_paths: list[AttackPath] = (
        dc_field(default_factory=list)
    )
    remediations: list[Remediation] = (
        dc_field(default_factory=list)
    )
    environment: (
        CollectedEnvironment | None
    ) = None
    collector_results: list[CollectorResult] = (
        dc_field(default_factory=list)
    )

    def build_graph(self) -> SecurityGraph:
        graph = SecurityGraph()

        graph.build(
            assets=list(self.assets),
            relationships=list(
                self.relationships
            ),
        )

        return graph


class ScanOverview(BaseModel):
    """Dashboard summary for one scan."""

    scan_id: str
    source: ScanSource
    environment: str
    status: ScanStatus
    created_at: datetime
    account_identifier: str | None = None
    regions: list[str] = Field(
        default_factory=list
    )

    assets: int
    relationships: int
    sensitive_assets: int
    internet_exposed_assets: int

    attack_paths: int
    findings: int

    severity: dict[str, int]

    highest_risk_score: int

    @property
    def mode(self) -> str:
        return (
            "local"
            if self.source == ScanSource.LOCAL_LAB
            else "aws"
        )
