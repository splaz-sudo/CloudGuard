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
                collector_results,
                regions_completed,
                regions_partial,
                regions_failed,
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
            record.regions_completed = regions_completed
            record.regions_partial = regions_partial
            record.regions_failed = regions_failed
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
                collector_results=collector_results,
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
        from cloudguard.aws_errors import CollectorResult
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

        # Generate mock collector results for LOCAL_LAB
        collector_results = [
            CollectorResult(
                collector="local_lab_ec2_instances",
                service="ec2",
                region=environment.region,
                status="success",
                resources_discovered=len(environment.instances),
                duration_ms=0.0,
                data=environment.instances,
            ),
            CollectorResult(
                collector="local_lab_ec2_security_groups",
                service="ec2",
                region=environment.region,
                status="success",
                resources_discovered=len(environment.security_groups),
                duration_ms=0.0,
                data=environment.security_groups,
            ),
            CollectorResult(
                collector="local_lab_s3_buckets",
                service="s3",
                region=environment.region,
                status="success",
                resources_discovered=len(environment.buckets),
                duration_ms=0.0,
                data=environment.buckets,
            ),
            CollectorResult(
                collector="local_lab_iam_roles",
                service="iam",
                region=environment.region,
                status="success",
                resources_discovered=len(environment.roles),
                duration_ms=0.0,
                data=environment.roles,
            ),
            CollectorResult(
                collector="local_lab_iam_instance_profiles",
                service="iam",
                region=environment.region,
                status="success",
                resources_discovered=len(environment.instance_profiles),
                duration_ms=0.0,
                data=environment.instance_profiles,
            ),
        ]

        return (
            result,
            environment.account_id,
            [environment.region],
            [],
            collector_results,
            [environment.region],  # regions_completed
            [],                    # regions_partial
            [],                    # regions_failed
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

        from cloudguard.aws_errors import (
            CollectorResult,
            classify_collector_error,
            safe_error_message,
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
        from cloudguard.retry import RetryConfig

        profile = (
            self.settings.aws_profile or None
        )

        # Parse cross-account roles from configuration
        cross_account_roles = self.settings.parse_cross_account_roles()

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

        retry_config = RetryConfig.standard()

        try:
            identity_session = AWSSession(
                profile_name=profile,
                region_name=(
                    regions[0]
                    if regions
                    else None
                ),
            )

            sts_collector = STSCollector(
                identity_session,
                retry_config=retry_config,
            )
            sts_result = sts_collector.get_identity()

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

        # Assume cross-account roles
        account_sessions = {}

        for role_config in cross_account_roles:
            try:
                assumed_session = self._assume_role(
                    identity_session,
                    role_config,
                    retry_config,
                )
                account_sessions[role_config["account_id"]] = {
                    "session": assumed_session,
                    "regions": regions,
                    "identity": role_config,
                }
            except Exception as error:
                logger.warning(
                    "Cross-account role assumption failed",
                    extra={
                        "event": "cross_account_failed",
                        "scan_id": record.scan_id,
                        "account_id": role_config["account_id"],
                        "error_type": type(error).__name__,
                        "error_message": str(error)[:300],
                    },
                )

        # Primary account (identity account) uses the original identity session
        primary_account_id = identity.account_id
        account_sessions[primary_account_id] = {
            "session": identity_session,
            "regions": regions,
            "identity": {"account_id": primary_account_id},
        }

        instances = []
        security_groups = []
        buckets = []
        roles = []
        users = []
        instance_profiles = []
        collector_results: list[CollectorResult] = []

        regions_completed = []
        regions_partial = []
        regions_failed = []

        def cancelled() -> bool:
            return bool(
                cancel_event
                and cancel_event.is_set()
            )

        for account_id, account_data in account_sessions.items():
            session = account_data["session"]
            account_regions = account_data["regions"]
            account_identity = account_data["identity"]

            for region in account_regions:
                if cancelled():
                    raise RuntimeError(
                        "Scan cancelled by user."
                    )

                record.regions_attempted.append(region)

            region_ec2_success = False
            region_ec2_failed = False

            try:
                ec2 = EC2Collector(
                    session,
                    retry_config=retry_config,
                )

                ec2_instances_result = ec2.collect_instances()
                collector_results.append(ec2_instances_result)

                if ec2_instances_result.status == "success":
                    instances.extend(
                        ec2_instances_result.data
                        if hasattr(
                            ec2_instances_result, "data"
                        )
                        else []
                    )
                    region_ec2_success = True

                ec2_sg_result = ec2.collect_security_groups()
                collector_results.append(ec2_sg_result)

                if ec2_sg_result.status == "success":
                    security_groups.extend(
                        ec2_sg_result.data
                        if hasattr(
                            ec2_sg_result, "data"
                        )
                        else []
                    )
                    region_ec2_success = True

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

                collector_results.append(
                    CollectorResult(
                        collector="ec2",
                        service="ec2",
                        region=region,
                        status="failed",
                        error_category=(
                            classify_collector_error(
                                error
                            )
                        ),
                        error_message=(
                            safe_error_message(
                                error
                            )
                        ),
                    )
                )
                region_ec2_failed = True

            # Track region status based on EC2 results
            if region_ec2_success and not region_ec2_failed:
                regions_completed.append(region)
            elif region_ec2_success and region_ec2_failed:
                regions_partial.append(region)
            else:
                regions_failed.append(region)

            try:
                s3 = S3Collector(
                    identity_session,
                    retry_config=retry_config,
                )
                s3_result = s3.collect_buckets()
                collector_results.append(s3_result)

                if s3_result.status == "success":
                    buckets.extend(
                        s3_result.data
                        if hasattr(
                            s3_result, "data"
                        )
                        else []
                    )

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

                collector_results.append(
                CollectorResult(
                    collector="s3",
                    service="s3",
                    region=None,
                    status="failed",
                    error_category=(
                        classify_collector_error(
                            error
                        )
                    ),
                    error_message=safe_error_message(
                        error
                    ),
                )
            )

        try:
            iam = IAMCollector(
                identity_session,
                retry_config=retry_config,
            )
            iam_roles_result = iam.collect_roles()
            collector_results.append(iam_roles_result)

            if iam_roles_result.status == "success":
                roles.extend(
                    iam_roles_result.data
                    if hasattr(
                        iam_roles_result, "data"
                    )
                    else []
                )

            iam_users_result = iam.collect_users()
            collector_results.append(iam_users_result)

            if iam_users_result.status == "success":
                users.extend(
                    iam_users_result.data
                    if hasattr(
                        iam_users_result, "data"
                    )
                    else []
                )

            iam_profiles_result = (
                iam.collect_instance_profiles()
            )
            collector_results.append(
                iam_profiles_result
            )

            if iam_profiles_result.status == "success":
                instance_profiles.extend(
                    iam_profiles_result.data
                    if hasattr(
                        iam_profiles_result, "data"
                    )
                    else []
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

            collector_results.append(
                CollectorResult(
                    collector="iam",
                    service="iam",
                    region=None,
                    status="failed",
                    error_category=(
                        classify_collector_error(
                            error
                        )
                    ),
                    error_message=safe_error_message(
                        error
                    ),
                )
            )

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

        failed_collectors = [
            f"{r.collector}:{r.region or r.service}"
            for r in collector_results
            if r.status == "failed"
        ]

        record.regions_completed = regions_completed
        record.regions_partial = regions_partial
        record.regions_failed = regions_failed

        return (
            result,
            identity.account_id,
            regions,
            failed_collectors,
            collector_results,
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
        collector_results: list | None = None,
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
            collector_results=collector_results or [],
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
