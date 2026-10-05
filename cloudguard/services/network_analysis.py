from __future__ import annotations

from typing import Any

from cloudguard.collectors.networking import (
    LoadBalancer,
    TargetGroup,
)
from cloudguard.inference.network_exposure import (
    ExposureEvidence,
    ExposureType,
    NetworkExposureEngine2,
)
from cloudguard.inference.network_risk import (
    ExposedService,
    NetworkRisk,
    calculate_network_risk,
)
from cloudguard.models.assets import AssetType


class NetworkAnalysisService:
    """
    Performs contextual network exposure analysis.

    Security-group configuration is correlated
    with the CloudGuard security graph and
    discovered attack paths.
    """

    INTERNET_CIDRS = {
        "0.0.0.0/0",
        "::/0",
    }

    def analyze(
        self,
        analysis_result: Any,
        instances: list[Any],
        security_groups: list[Any],
        environment: Any = None,
    ) -> list[NetworkRisk]:

        groups_by_id = {
            group.group_id: group
            for group in security_groups
        }

        risks: list[NetworkRisk] = []

        # Use NetworkExposureEngine2 if we have full environment data
        exposure_engine = None
        if environment is not None:
            try:
                exposure_engine = NetworkExposureEngine2(
                    vpcs=getattr(environment, "vpcs", []),
                    subnets=getattr(environment, "subnets", []),
                    route_tables=getattr(environment, "route_tables", []),
                    internet_gateways=getattr(environment, "internet_gateways", []),
                    nat_gateways=getattr(environment, "nat_gateways", []),
                    network_acls=getattr(environment, "network_acls", []),
                    network_interfaces=getattr(environment, "network_interfaces", []),
                    elastic_ips=getattr(environment, "elastic_ips", []),
                    load_balancers=getattr(environment, "load_balancers", []),
                    target_groups=getattr(environment, "target_groups", []),
                    security_groups=security_groups,
                    instances=instances,
                )
            except Exception:
                exposure_engine = None

        for instance in instances:
            risk = self._analyze_instance(
                analysis_result=analysis_result,
                instance=instance,
                groups_by_id=groups_by_id,
                exposure_engine=exposure_engine,
            )

            risks.append(risk)

        risks.sort(
            key=lambda item: (
                item.risk_score
            ),
            reverse=True,
        )

        return risks

    def _analyze_instance(
        self,
        *,
        analysis_result: Any,
        instance: Any,
        groups_by_id: dict[str, Any],
        exposure_engine: Any = None,
    ) -> NetworkRisk:

        graph = (
            analysis_result
            .security_graph
        )

        asset = graph.get_asset(
            instance.instance_id
        )

        asset_name = (
            asset.name
            if asset is not None
            else instance.instance_id
        )

        metadata = (
            dict(asset.metadata)
            if asset is not None
            else {}
        )

        exposed_services: list[
            ExposedService
        ] = []

        security_group_names: list[
            str
        ] = []

        for group_id in (
            instance.security_group_ids
        ):
            group = groups_by_id.get(
                group_id
            )

            if group is None:
                continue

            security_group_names.append(
                group.group_name
            )

            for rule in (
                group.inbound_rules
            ):
                internet_sources = [
                    source
                    for source in rule.sources
                    if source
                    in self.INTERNET_CIDRS
                ]

                if not internet_sources:
                    continue

                exposed_services.append(
                    ExposedService(
                        protocol=rule.protocol,
                        from_port=(
                            rule.from_port
                        ),
                        to_port=(
                            rule.to_port
                        ),
                        sources=(
                            internet_sources
                        ),
                        security_group_id=(
                            group.group_id
                        ),
                        security_group_name=(
                            group.group_name
                        ),
                    )
                )

        attached_identities = (
            self._find_attached_identities(
                analysis_result,
                instance.instance_id,
            )
        )

        attack_paths = (
            self._find_attack_paths(
                analysis_result,
                instance.instance_id,
            )
        )

        sensitive_resources = (
            self._find_sensitive_resources(
                analysis_result,
                attack_paths,
            )
        )

        # Use exposure engine for enhanced evidence if available
        exposure_evidence = None
        if exposure_engine is not None:
            # Create a mock asset for the instance
            from cloudguard.models.assets import CloudAsset, AssetType
            mock_asset = CloudAsset(
                id=instance.instance_id,
                name=instance.instance_id,
                asset_type=AssetType.EC2,
                account_id="",
                region=instance.region,
            )
            exposure_evidence = exposure_engine.analyze_exposure(mock_asset)

        return calculate_network_risk(
            asset_id=instance.instance_id,
            asset_name=asset_name,
            public_ip=instance.public_ip,
            security_groups=(
                security_group_names
            ),
            exposed_services=(
                exposed_services
            ),
            attached_identities=(
                attached_identities
            ),
            sensitive_resources=(
                sensitive_resources
            ),
            attack_paths=attack_paths,
            metadata=metadata,
        )

    @staticmethod
    def _find_attached_identities(
        analysis_result: Any,
        asset_id: str,
    ) -> list[str]:

        graph = (
            analysis_result
            .security_graph
        )

        identities: list[str] = []

        for target in (
            graph.graph.successors(
                asset_id
            )
        ):
            target_asset = (
                graph.get_asset(target)
            )

            if target_asset is None:
                continue

            asset_type = getattr(
                target_asset.asset_type,
                "value",
                target_asset.asset_type,
            )

            if str(asset_type) in {
                "iam_role",
                "iam_user",
            }:
                identities.append(
                    target
                )

        return identities

    @staticmethod
    def _find_attack_paths(
        analysis_result: Any,
        asset_id: str,
    ) -> list[list[str]]:

        paths: list[list[str]] = []

        for path in (
            analysis_result.attack_paths
        ):
            nodes = list(
                path.nodes
            )

            if asset_id in nodes:
                paths.append(nodes)

        return paths

    @staticmethod
    def _find_sensitive_resources(
        analysis_result: Any,
        attack_paths: list[list[str]],
    ) -> list[str]:

        graph = (
            analysis_result
            .security_graph
        )

        resources: list[str] = []

        for path in attack_paths:
            for node_id in path:
                asset = graph.get_asset(
                    node_id
                )

                if asset is None:
                    continue

                if asset.sensitive:
                    resources.append(
                        node_id
                    )

        return sorted(
            set(resources)
        )