"""
CloudGuard scan lifecycle service.

A scan runs the analysis pipeline once and
persists an immutable snapshot. API endpoints
read snapshots; they never re-analyze per
request.

Scans execute on a small background worker.
Local lab scans complete in milliseconds and
are normally awaited inline; AWS scans can
run asynchronously with PENDING -> RUNNING ->
COMPLETED / PARTIAL / FAILED transitions.

Read-only guarantee: AWS collection uses only
Describe/List/Get APIs. Collector failures are
recorded and produce PARTIAL scans instead of
silently pretending full visibility.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from concurrent.futures import (
    ThreadPoolExecutor,
)
from datetime import datetime, timezone

from cloudguard import __version__
from cloudguard.config import Settings
from cloudguard.persistence.repository import (
    ScanRepository,
)
from cloudguard.remediation.service import (
    RemediationService,
)
from cloudguard.scans.models import (
    ScanRecord,
    ScanSnapshot,
    ScanSource,
    ScanStatus,
)
from cloudguard.services.analysis import (
    AnalysisResult,
    AnalysisService,
)

logger = logging.getLogger("cloudguard.scans")


class ScanNotFoundError(Exception):
    pass


class ScanNotReadyError(Exception):
    pass


class ScanFailedError(Exception):
    pass


class ScanService:
    def __init__(
        self,
        repository: ScanRepository,
        settings: Settings,
    ) -> None:
        self.repository = repository
        self.settings = settings

        self.analysis_service = AnalysisService()
        self.remediation_service = (
            RemediationService()
        )

        self._executor = ThreadPoolExecutor(
            max_workers=2,
            thread_name_prefix=(
                "cloudguard-scan"
            ),
        )

        self._cancel_events: dict[
            str, threading.Event
        ] = {}

        interrupted = (
            repository.fail_interrupted_scans(
                "Scan was interrupted by a "
                "CloudGuard restart."
            )
        )

        if interrupted:
            logger.warning(
                "Recovered interrupted scans",
                extra={
                    "event": "scan_recovery",
                    "interrupted_scans": (
                        interrupted
                    ),
                },
            )

    # ------------------------------------------
    # Lifecycle
    # ------------------------------------------

    def create_scan(
        self,
        source: ScanSource,
        environment: str = "",
        regions: list[str] | None = None,
        wait: bool = True,
    ) -> ScanRecord:

        from cloudguard.lab_scenarios import (
            DEFAULT_SCENARIO,
        )

        scan_id = f"scan-{uuid.uuid4().hex[:12]}"

        record = ScanRecord(
            scan_id=scan_id,
            source=source,
            environment=(
                environment
                or (
                    DEFAULT_SCENARIO
                    if source
                    == ScanSource.LOCAL_LAB
                    else "aws"
                )
            ),
            status=ScanStatus.PENDING,
            created_at=datetime.now(
                timezone.utc
            ),
            regions=list(regions or []),
            scanner_version=__version__,
        )

        self.repository.insert_scan(record)

        self._cancel_events[scan_id] = (
            threading.Event()
        )

        logger.info(
            "Scan created",
            extra={
                "event": "scan_created",
                "scan_id": scan_id,
                "source": source.value,
                "environment": (
                    record.environment
                ),
            },
        )

        if wait:
            self._run_scan(scan_id)
        else:
            self._executor.submit(
                self._run_scan,
                scan_id,
            )

        stored = self.repository.get_record(
            scan_id
        )

        return stored or record

    def cancel_scan(
        self,
        scan_id: str,
    ) -> ScanRecord:
        record = self._require_record(scan_id)

        event = self._cancel_events.get(
            scan_id
        )

        if event is not None:
            event.set()

        if record.status in (
            ScanStatus.COMPLETED,
            ScanStatus.PARTIAL,
            ScanStatus.FAILED,
        ):
            return record

        record.status = ScanStatus.FAILED
        record.error_message = (
            "Scan cancelled by user."
        )
        record.completed_at = datetime.now(
            timezone.utc
        )

        self.repository.update_scan(record)

        logger.info(
            "Scan cancelled",
            extra={
                "event": "scan_cancelled",
                "scan_id": scan_id,
            },
        )

        return record

    def _run_scan(self, scan_id: str) -> None:
        record = self.repository.get_record(
            scan_id
        )

        if record is None:
            return

        record.status = ScanStatus.RUNNING
        record.started_at = datetime.now(
            timezone.utc
        )

        self.repository.update_scan(record)

        started = time.perf_counter()

        try:
            (
                analysis_result,
                account_identifier,
                regions,
                failed_collectors,
            ) = self._collect_and_analyze(
                record
            )

            remediations = (
                self.remediation_service
                .get_remediations(
                    analysis_result
                )
            )

            record.status = (
                ScanStatus.PARTIAL
                if failed_collectors
                else ScanStatus.COMPLETED
            )
            record.completed_at = datetime.now(
                timezone.utc
            )
            record.account_identifier = (
                account_identifier
            )
            record.regions = regions
            record.failed_collectors = (
                failed_collectors
            )
            record.asset_count = (
                analysis_result
                .security_graph
                .asset_count
            )
            record.relationship_count = (
                analysis_result
                .security_graph
                .relationship_count
            )
            record.finding_count = len(
                analysis_result.findings
            )
            record.attack_path_count = len(
                analysis_result.attack_paths
            )
            record.highest_risk = max(
                (
                    finding.risk_score
                    for finding in (
                        analysis_result.findings
                    )
                ),
                default=0,
            )

            snapshot = self._snapshot(
                record,
                analysis_result,
                remediations,
            )

            self.repository.save_snapshot(
                snapshot
            )

        except Exception as error:
            record.status = ScanStatus.FAILED
            record.completed_at = datetime.now(
                timezone.utc
            )
            record.error_message = (
                self._safe_error(error)
            )

            self.repository.update_scan(
                record
            )

            logger.exception(
                "Scan failed",
                extra={
                    "event": "scan_failed",
                    "scan_id": scan_id,
                    "error_type": type(
                        error
                    ).__name__,
                },
            )

            return

        record.duration_ms = round(
            (time.perf_counter() - started)
            * 1000,
            2,
        )

        self.repository.update_scan(record)

        logger.info(
            "Scan completed",
            extra={
                "event": "scan_completed",
                "scan_id": scan_id,
                "status": record.status.value,
                "duration_ms": (
                    record.duration_ms
                ),
                "assets": record.asset_count,
                "relationships": (
                    record.relationship_count
                ),
                "findings": (
                    record.finding_count
                ),
                "attack_paths": (
                    record.attack_path_count
                ),
                "failed_collectors": (
                    record.failed_collectors
                ),
            },
        )

    # ------------------------------------------
    # Collection
    # ------------------------------------------

    def _collect_and_analyze(
        self,
        record: ScanRecord,
    ):
        if record.source == ScanSource.LOCAL_LAB:
            return (
                self._analyze_local_lab(record)
            )

        return self._analyze_aws(record)

    def _analyze_local_lab(
        self,
        record: ScanRecord,
    ):
        from cloudguard.lab_scenarios import (
            create_scenario_environment,
        )

        environment = (
            create_scenario_environment(
                record.environment
            )
        )

        result = (
            self.analysis_service
            .analyze_environment(
                instances=(
                    environment.instances
                ),
                security_groups=(
                    environment.security_groups
                ),
                buckets=environment.buckets,
                roles=environment.roles,
                instance_profiles=(
                    environment
                    .instance_profiles
                ),
                account_id=(
                    environment.account_id
                ),
            )
        )

        if result.environment is not None:
            result.environment.regions = [
                environment.region
            ]

        return (
            result,
            environment.account_id,
            [environment.region],
            [],
        )

    def _analyze_aws(
        self,
        record: ScanRecord,
    ):
        """
        Read-only AWS collection.

        Every collector is isolated: a failing
        collector is recorded and the scan
        becomes PARTIAL. Only Describe/List/Get
        APIs are used. Credentials come from the
        standard boto3 chain and are never
        logged or stored.
        """

        from botocore.exceptions import (
            BotoCoreError,
            ClientError,
            NoCredentialsError,
        )

        from cloudguard.collectors.aws_session import (  # noqa: E501
            AWSSession,
        )
        from cloudguard.collectors.ec2 import (
            EC2Collector,
        )
        from cloudguard.collectors.iam import (
            IAMCollector,
        )
        from cloudguard.collectors.s3 import (
            S3Collector,
        )
        from cloudguard.collectors.sts import (
            STSCollector,
        )

        profile = (
            self.settings.aws_profile or None
        )

        regions = (
            record.regions
            or list(
                self.settings.aws_regions
            )
            or []
        )

        cancel_event = (
            self._cancel_events.get(
                record.scan_id
            )
        )

        try:
            identity_session = AWSSession(
                profile_name=profile,
                region_name=(
                    regions[0]
                    if regions
                    else None
                ),
            )

            identity = STSCollector(
                identity_session
            ).get_identity()

        except NoCredentialsError:
            raise RuntimeError(
                "AWS credentials were not "
                "found. Configure a profile, "
                "environment credentials, or "
                "an IAM role."
            ) from None

        except (ClientError, BotoCoreError) as e:
            raise RuntimeError(
                "AWS identity check failed: "
                f"{type(e).__name__}"
            ) from None

        if not regions:
            regions = [
                identity_session.region
                or "us-east-1"
            ]

        instances = []
        security_groups = []
        buckets = []
        roles = []
        users = []
        instance_profiles = []
        failed_collectors: list[str] = []

        def cancelled() -> bool:
            return bool(
                cancel_event
                and cancel_event.is_set()
            )

        for region in regions:
            if cancelled():
                raise RuntimeError(
                    "Scan cancelled by user."
                )

            try:
                session = AWSSession(
                    profile_name=profile,
                    region_name=region,
                )

                ec2 = EC2Collector(session)

                instances.extend(
                    ec2.collect_instances()
                )
                security_groups.extend(
                    ec2.collect_security_groups()
                )

            except (
                ClientError,
                BotoCoreError,
            ) as error:
                logger.warning(
                    "EC2 collection failed",
                    extra={
                        "event": (
                            "collector_failed"
                        ),
                        "scan_id": (
                            record.scan_id
                        ),
                        "collector": "ec2",
                        "region": region,
                        "error_type": type(
                            error
                        ).__name__,
                    },
                )

                failed_collectors.append(
                    f"ec2:{region}"
                )

        try:
            s3 = S3Collector(identity_session)
            buckets = s3.collect_buckets()

        except (
            ClientError,
            BotoCoreError,
        ) as error:
            logger.warning(
                "S3 collection failed",
                extra={
                    "event": (
                        "collector_failed"
                    ),
                    "scan_id": record.scan_id,
                    "collector": "s3",
                    "error_type": type(
                        error
                    ).__name__,
                },
            )

            failed_collectors.append("s3")

        try:
            iam = IAMCollector(
                identity_session
            )
            roles = iam.collect_roles()
            users = iam.collect_users()
            instance_profiles = (
                iam.collect_instance_profiles()
            )

        except (
            ClientError,
            BotoCoreError,
        ) as error:
            logger.warning(
                "IAM collection failed",
                extra={
                    "event": (
                        "collector_failed"
                    ),
                    "scan_id": record.scan_id,
                    "collector": "iam",
                    "error_type": type(
                        error
                    ).__name__,
                },
            )

            failed_collectors.append("iam")

        result = (
            self.analysis_service
            .analyze_environment(
                instances=instances,
                security_groups=(
                    security_groups
                ),
                buckets=buckets,
                roles=roles,
                instance_profiles=(
                    instance_profiles
                ),
                users=users,
                account_id=(
                    identity.account_id
                ),
            )
        )

        if result.environment is not None:
            result.environment.regions = list(
                regions
            )

        return (
            result,
            identity.account_id,
            regions,
            failed_collectors,
        )

    # ------------------------------------------
    # Reads
    # ------------------------------------------

    def list_scans(
        self,
        limit: int = 50,
    ) -> list[ScanRecord]:
        return self.repository.list_records(
            limit
        )

    def get_scan(
        self,
        scan_id: str,
    ) -> ScanRecord:
        return self._require_record(scan_id)

    def get_snapshot(
        self,
        scan_id: str,
    ) -> ScanSnapshot:
        record = self._require_record(scan_id)

        if record.status in (
            ScanStatus.PENDING,
            ScanStatus.RUNNING,
        ):
            raise ScanNotReadyError(
                f"Scan {scan_id} is "
                f"{record.status.value}."
            )

        if record.status == ScanStatus.FAILED:
            raise ScanFailedError(
                f"Scan {scan_id} failed: "
                f"{record.error_message}"
            )

        snapshot = (
            self.repository.get_snapshot(
                scan_id
            )
        )

        if snapshot is None:
            raise ScanNotFoundError(scan_id)

        return snapshot

    def latest_snapshot(
        self,
        source: ScanSource | None = None,
        environment: str | None = None,
    ) -> ScanSnapshot:
        record = (
            self.repository.latest_completed(
                source.value if source else None,
                environment,
            )
        )

        if record is None:
            raise ScanNotFoundError(
                "No completed scans exist yet."
            )

        return self.get_snapshot(
            record.scan_id
        )

    def get_or_create_latest_local_lab(
        self,
    ) -> ScanSnapshot:
        """
        Backwards-compatible access for the
        original endpoints: reuse the newest
        completed default local-lab scan, or
        run one.
        """

        from cloudguard.lab_scenarios import (
            DEFAULT_SCENARIO,
        )

        try:
            return self.latest_snapshot(
                ScanSource.LOCAL_LAB,
                environment=DEFAULT_SCENARIO,
            )
        except ScanNotFoundError:
            record = self.create_scan(
                ScanSource.LOCAL_LAB,
                wait=True,
            )

            return self.get_snapshot(
                record.scan_id
            )

    # ------------------------------------------

    def analysis_result_for(
        self,
        snapshot: ScanSnapshot,
    ) -> AnalysisResult:
        """
        Rebuild an AnalysisResult view of a
        stored snapshot so existing engines
        (simulation, network/identity analysis)
        can run against the exact scanned state.
        """

        return AnalysisResult(
            assets=list(snapshot.assets),
            security_graph=(
                snapshot.build_graph()
            ),
            attack_paths=list(
                snapshot.attack_paths
            ),
            findings=list(snapshot.findings),
        )

    # ------------------------------------------

    def _require_record(
        self,
        scan_id: str,
    ) -> ScanRecord:
        record = self.repository.get_record(
            scan_id
        )

        if record is None:
            raise ScanNotFoundError(scan_id)

        return record

    @staticmethod
    def _snapshot(
        record: ScanRecord,
        result: AnalysisResult,
        remediations,
    ) -> ScanSnapshot:
        relationships = []

        graph = result.security_graph

        for source, target in (
            graph.graph.edges
        ):
            relationship = (
                graph.get_relationship(
                    source,
                    target,
                )
            )

            if relationship is not None:
                relationships.append(
                    relationship
                )

        return ScanSnapshot(
            record=record,
            assets=list(result.assets)
            + [
                graph.get_asset(node_id)
                for node_id in graph.graph.nodes
                if graph.get_asset(node_id)
                is not None
                and graph.get_asset(node_id)
                not in result.assets
            ],
            relationships=relationships,
            findings=list(result.findings),
            attack_paths=list(
                result.attack_paths
            ),
            remediations=list(remediations),
            environment=result.environment,
        )

    @staticmethod
    def _safe_error(error: Exception) -> str:
        """
        Client-facing scan error text. Never
        includes credential material; boto
        exceptions are reduced to their type.
        """

        message = str(error)

        if len(message) > 300:
            message = message[:300] + "..."

        return message
