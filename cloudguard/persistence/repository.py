"""
Scan repository: the only module containing
SQL for scan persistence.

Domain objects are stored as JSON documents in
structured rows with indexed key columns.
Nothing is pickled; nothing business-level
knows about SQL.
"""

from __future__ import annotations

import json

from cloudguard.collectors import (
    CollectedEnvironment,
)
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
from cloudguard.findings.models import Finding
from cloudguard.graph.attack_paths import (
    AttackPath,
)
from cloudguard.models.assets import CloudAsset
from cloudguard.models.relationships import (
    Relationship,
)
from cloudguard.persistence.database import (
    Database,
)
from cloudguard.aws_errors import CollectorResult
from cloudguard.remediation.models import (
    Remediation,
)
from cloudguard.scans.models import (
    ScanRecord,
    ScanSnapshot,
    ScanStatus,
)


class ScanRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    # ------------------------------------------
    # Scan records
    # ------------------------------------------

    def insert_scan(
        self,
        record: ScanRecord,
    ) -> None:
        self._write_record(record)

    def update_scan(
        self,
        record: ScanRecord,
    ) -> None:
        self._write_record(record)

    def _write_record(
        self,
        record: ScanRecord,
    ) -> None:
        data = record.model_dump(mode="json")

        self.database.execute(
            """
            INSERT OR REPLACE INTO scans (
                scan_id, source, environment,
                status, created_at, started_at,
                completed_at, account_identifier,
                regions_json, asset_count,
                relationship_count, finding_count,
                attack_path_count, highest_risk,
                failed_collectors_json,
                error_message, scanner_version,
                duration_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?,
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["scan_id"],
                data["source"],
                data["environment"],
                data["status"],
                data["created_at"],
                data["started_at"],
                data["completed_at"],
                data["account_identifier"],
                json.dumps(data["regions"]),
                data["asset_count"],
                data["relationship_count"],
                data["finding_count"],
                data["attack_path_count"],
                data["highest_risk"],
                json.dumps(
                    data["failed_collectors"]
                ),
                data["error_message"],
                data["scanner_version"],
                data["duration_ms"],
            ),
        )

    def get_record(
        self,
        scan_id: str,
    ) -> ScanRecord | None:
        cursor = self.database.execute(
            "SELECT * FROM scans WHERE scan_id = ?",
            (scan_id,),
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return self._record_from_row(row)

    def list_records(
        self,
        limit: int = 50,
    ) -> list[ScanRecord]:
        cursor = self.database.execute(
            """
            SELECT * FROM scans
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        )

        return [
            self._record_from_row(row)
            for row in cursor.fetchall()
        ]

    def latest_completed(
        self,
        source: str | None = None,
        environment: str | None = None,
    ) -> ScanRecord | None:
        sql = (
            "SELECT * FROM scans "
            "WHERE status IN "
            "('completed', 'partial')"
        )

        parameters: list[str] = []

        if source is not None:
            sql += " AND source = ?"
            parameters.append(source)

        if environment is not None:
            sql += " AND environment = ?"
            parameters.append(environment)

        sql += (
            " ORDER BY created_at DESC"
            " LIMIT 1"
        )

        cursor = self.database.execute(
            sql,
            tuple(parameters),
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return self._record_from_row(row)

    def fail_interrupted_scans(
        self,
        error_message: str,
    ) -> int:
        """
        Recovery: scans left PENDING/RUNNING by a
        previous process cannot resume and are
        marked FAILED.
        """

        cursor = self.database.execute(
            """
            UPDATE scans
            SET status = ?, error_message = ?
            WHERE status IN ('pending', 'running')
            """,
            (
                ScanStatus.FAILED.value,
                error_message,
            ),
        )

        return cursor.rowcount

    # ------------------------------------------
    # Snapshots
    # ------------------------------------------

    def save_snapshot(
        self,
        snapshot: ScanSnapshot,
    ) -> None:
        record = snapshot.record

        self._write_record(record)

        self.database.executemany(
            """
            INSERT OR REPLACE INTO scan_assets (
                scan_id, asset_id, asset_type,
                name, sensitive, internet_exposed,
                region, data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    record.scan_id,
                    asset.id,
                    asset.asset_type.value,
                    asset.name,
                    int(asset.sensitive),
                    int(asset.internet_exposed),
                    asset.region,
                    json.dumps(
                        asset.model_dump(
                            mode="json"
                        )
                    ),
                )
                for asset in snapshot.assets
            ],
        )

        self.database.executemany(
            """
            INSERT OR REPLACE INTO scan_relationships (
                scan_id, relationship_id, source,
                target, relationship_type, data_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    record.scan_id,
                    relationship.relationship_id,
                    relationship.source,
                    relationship.target,
                    relationship.relationship_type.value,
                    json.dumps(
                        relationship.model_dump(
                            mode="json"
                        )
                    ),
                )
                for relationship in (
                    snapshot.relationships
                )
            ],
        )

        self.database.executemany(
            """
            INSERT OR REPLACE INTO scan_findings (
                scan_id, finding_id, fingerprint,
                severity, category, risk_score,
                data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    record.scan_id,
                    finding.id,
                    finding.fingerprint,
                    finding.severity.value,
                    finding.category.value,
                    finding.risk_score,
                    json.dumps(
                        finding.model_dump(
                            mode="json"
                        )
                    ),
                )
                for finding in snapshot.findings
            ],
        )

        self.database.executemany(
            """
            INSERT OR REPLACE INTO scan_attack_paths (
                scan_id, path_id, source, target,
                risk_score, data_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    record.scan_id,
                    path.path_id,
                    path.source,
                    path.target,
                    path.risk_score,
                    json.dumps(
                        path.model_dump(
                            mode="json"
                        )
                    ),
                )
                for path in snapshot.attack_paths
            ],
        )

        self.database.executemany(
            """
            INSERT OR REPLACE INTO scan_remediations (
                scan_id, remediation_id,
                action_type, data_json
            ) VALUES (?, ?, ?, ?)
            """,
            [
                (
                    record.scan_id,
                    remediation.remediation_id,
                    remediation.action_type.value,
                    json.dumps(
                        remediation.model_dump(
                            mode="json"
                        )
                    ),
                )
                for remediation in (
                    snapshot.remediations
                )
            ],
        )

        if snapshot.environment is not None:
            self.database.execute(
                """
                INSERT OR REPLACE INTO
                scan_environments (
                    scan_id, data_json
                ) VALUES (?, ?)
                """,
                (
                    record.scan_id,
                    json.dumps(
                        self._environment_to_dict(
                            snapshot
                            .environment
                        )
                    ),
                ),
            )

        self._save_collector_results(
            record.scan_id,
            snapshot.collector_results or [],
        )

    def _save_collector_results(
        self,
        scan_id: str,
        results: list[CollectorResult],
    ) -> None:
        import json

        self.database.executemany(
            """
            INSERT OR REPLACE INTO scan_collector_results (
                scan_id, collector, service, region,
                status, resources_discovered,
                duration_ms, error_category,
                error_message, coverage_limitation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_id,
                    result.collector,
                    result.service,
                    result.region,
                    result.status,
                    result.resources_discovered,
                    result.duration_ms,
                    result.error_category.value
                    if result.error_category
                    else None,
                    result.error_message,
                    result.coverage_limitation,
                )
                for result in results
            ],
        )

    def get_collector_results(
        self,
        scan_id: str,
    ) -> list[CollectorResult]:
        from cloudguard.aws_errors import (
            CollectorResult,
            CollectorErrorCategory,
        )

        rows = self.database.execute(
            "SELECT * FROM scan_collector_results "
            "WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()

        results: list[CollectorResult] = []

        for row in rows:
            error_category = None
            if row["error_category"]:
                error_category = CollectorErrorCategory(
                    row["error_category"]
                )

            results.append(
                CollectorResult(
                    collector=row["collector"],
                    service=row["service"],
                    region=row["region"],
                    status=row["status"],
                    resources_discovered=row[
                        "resources_discovered"
                    ],
                    duration_ms=row["duration_ms"],
                    error_category=error_category,
                    error_message=row["error_message"],
                    coverage_limitation=row[
                        "coverage_limitation"
                    ],
                )
            )

        return results

    @staticmethod
    def _environment_to_dict(
        environment: CollectedEnvironment,
    ) -> dict:
        return {
            "instances": [
                item.model_dump(mode="json")
                for item in (
                    environment.instances
                )
            ],
            "security_groups": [
                item.model_dump(mode="json")
                for item in (
                    environment.security_groups
                )
            ],
            "buckets": [
                item.model_dump(mode="json")
                for item in (
                    environment.buckets
                )
            ],
            "roles": [
                item.model_dump(mode="json")
                for item in environment.roles
            ],
            "users": [
                item.model_dump(mode="json")
                for item in environment.users
            ],
            "instance_profiles": [
                item.model_dump(mode="json")
                for item in (
                    environment
                    .instance_profiles
                )
            ],
            "account_id": (
                environment.account_id
            ),
            "regions": environment.regions,
        }

    @staticmethod
    def _environment_from_dict(
        data: dict,
    ) -> CollectedEnvironment:
        return CollectedEnvironment(
            instances=[
                EC2Instance(**item)
                for item in data.get(
                    "instances",
                    [],
                )
            ],
            security_groups=[
                SecurityGroup(**item)
                for item in data.get(
                    "security_groups",
                    [],
                )
            ],
            buckets=[
                S3Bucket(**item)
                for item in data.get(
                    "buckets",
                    [],
                )
            ],
            roles=[
                IAMRole(**item)
                for item in data.get(
                    "roles",
                    [],
                )
            ],
            users=[
                IAMUser(**item)
                for item in data.get(
                    "users",
                    [],
                )
            ],
            instance_profiles=[
                InstanceProfile(**item)
                for item in data.get(
                    "instance_profiles",
                    [],
                )
            ],
            account_id=data.get(
                "account_id",
                "",
            ),
            regions=data.get(
                "regions",
                [],
            ),
        )

    def get_snapshot(
        self,
        scan_id: str,
    ) -> ScanSnapshot | None:
        record = self.get_record(scan_id)

        if record is None:
            return None

        snapshot = ScanSnapshot(record=record)

        for row in self.database.execute(
            "SELECT data_json FROM scan_assets "
            "WHERE scan_id = ?",
            (scan_id,),
        ).fetchall():
            snapshot.assets.append(
                CloudAsset(
                    **json.loads(
                        row["data_json"]
                    )
                )
            )

        for row in self.database.execute(
            "SELECT data_json FROM "
            "scan_relationships "
            "WHERE scan_id = ?",
            (scan_id,),
        ).fetchall():
            snapshot.relationships.append(
                Relationship(
                    **json.loads(
                        row["data_json"]
                    )
                )
            )

        for row in self.database.execute(
            "SELECT data_json FROM scan_findings "
            "WHERE scan_id = ?",
            (scan_id,),
        ).fetchall():
            snapshot.findings.append(
                Finding(
                    **json.loads(
                        row["data_json"]
                    )
                )
            )

        for row in self.database.execute(
            "SELECT data_json FROM "
            "scan_attack_paths "
            "WHERE scan_id = ?",
            (scan_id,),
        ).fetchall():
            snapshot.attack_paths.append(
                AttackPath(
                    **json.loads(
                        row["data_json"]
                    )
                )
            )

        for row in self.database.execute(
            "SELECT data_json FROM "
            "scan_remediations "
            "WHERE scan_id = ?",
            (scan_id,),
        ).fetchall():
            snapshot.remediations.append(
                Remediation(
                    **json.loads(
                        row["data_json"]
                    )
                )
            )

        environment_row = (
            self.database.execute(
                "SELECT data_json FROM "
                "scan_environments "
                "WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        )

        if environment_row is not None:
            snapshot.environment = (
                self._environment_from_dict(
                    json.loads(
                        environment_row[
                            "data_json"
                        ]
                    )
                )
            )

        snapshot.collector_results = self.get_collector_results(scan_id)

        return snapshot

    # ------------------------------------------

    @staticmethod
    def _record_from_row(row) -> ScanRecord:
        return ScanRecord(
            scan_id=row["scan_id"],
            source=row["source"],
            environment=row["environment"],
            status=row["status"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            account_identifier=(
                row["account_identifier"]
            ),
            regions=json.loads(
                row["regions_json"]
            ),
            asset_count=row["asset_count"],
            relationship_count=(
                row["relationship_count"]
            ),
            finding_count=row["finding_count"],
            attack_path_count=(
                row["attack_path_count"]
            ),
            highest_risk=row["highest_risk"],
            failed_collectors=json.loads(
                row["failed_collectors_json"]
            ),
            error_message=row["error_message"],
            scanner_version=(
                row["scanner_version"]
            ),
            duration_ms=row["duration_ms"],
        )
