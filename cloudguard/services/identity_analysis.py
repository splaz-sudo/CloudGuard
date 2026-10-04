from __future__ import annotations

from typing import Any

from cloudguard.inference.identity_risk import (
    IDENTITY_TYPES,
    IdentityRisk,
    calculate_identity_risk,
)


class IdentityAnalysisService:
    """
    Builds contextual IAM identity risk from an
    existing CloudGuard analysis result.

    This service intentionally uses CloudGuard's
    observed relationships rather than claiming
    complete AWS effective-permission evaluation.
    """

    def analyze(
        self,
        analysis_result: Any,
    ) -> list[IdentityRisk]:
        graph = (
            analysis_result
            .security_graph
        )

        identities: list[
            IdentityRisk
        ] = []

        for node_id in graph.graph.nodes:
            asset = graph.get_asset(
                node_id
            )

            if asset is None:
                continue

            asset_type = (
                self._enum_value(
                    asset.asset_type
                )
            )

            if (
                asset_type
                not in IDENTITY_TYPES
            ):
                continue

            identities.append(
                self._analyze_identity(
                    analysis_result,
                    node_id,
                    asset,
                )
            )

        identities.sort(
            key=lambda item: (
                item.risk_score
            ),
            reverse=True,
        )

        return identities

    def _analyze_identity(
        self,
        analysis_result: Any,
        identity_id: str,
        identity: Any,
    ) -> IdentityRisk:
        graph = (
            analysis_result
            .security_graph
        )

        permissions: list[str] = []
        connected_assets: list[str] = []
        exposed_workloads: list[str] = []
        sensitive_resources: list[str] = []

        network_graph = graph.graph

        neighbors = set(
            network_graph.predecessors(
                identity_id
            )
        )

        neighbors.update(
            network_graph.successors(
                identity_id
            )
        )

        for neighbor_id in neighbors:
            neighbor = graph.get_asset(
                neighbor_id
            )

            if neighbor is None:
                continue

            connected_assets.append(
                neighbor_id
            )

            if neighbor.internet_exposed:
                exposed_workloads.append(
                    neighbor_id
                )

            if neighbor.sensitive:
                sensitive_resources.append(
                    neighbor_id
                )

        for source, target in (
            network_graph.edges
        ):
            if (
                source != identity_id
                and target != identity_id
            ):
                continue

            relationship = (
                graph.get_relationship(
                    source,
                    target,
                )
            )

            if relationship is None:
                continue

            permissions.extend(
                self._relationship_permissions(
                    relationship
                )
            )

            other_id = (
                target
                if source == identity_id
                else source
            )

            other_asset = (
                graph.get_asset(
                    other_id
                )
            )

            if other_asset is None:
                continue

            if other_asset.sensitive:
                sensitive_resources.append(
                    other_id
                )

            if (
                other_asset
                .internet_exposed
            ):
                exposed_workloads.append(
                    other_id
                )

        identity_paths: list[
            list[str]
        ] = []

        for path in (
            analysis_result.attack_paths
        ):
            path_nodes = list(
                path.nodes
            )

            if identity_id not in path_nodes:
                continue

            identity_paths.append(
                path_nodes
            )

            for path_node_id in path_nodes:
                path_asset = (
                    graph.get_asset(
                        path_node_id
                    )
                )

                if path_asset is None:
                    continue

                if (
                    path_asset
                    .internet_exposed
                ):
                    exposed_workloads.append(
                        path_node_id
                    )

                if path_asset.sensitive:
                    sensitive_resources.append(
                        path_node_id
                    )

        metadata = dict(
            getattr(
                identity,
                "metadata",
                {},
            )
            or {}
        )

        return calculate_identity_risk(
            identity_id=identity_id,
            identity_name=identity.name,
            identity_type=(
                self._enum_value(
                    identity.asset_type
                )
            ),
            permissions=permissions,
            connected_assets=(
                connected_assets
            ),
            exposed_workloads=(
                exposed_workloads
            ),
            sensitive_resources=(
                sensitive_resources
            ),
            attack_paths=identity_paths,
            metadata=metadata,
        )

    @staticmethod
    def _relationship_permissions(
        relationship: Any,
    ) -> list[str]:
        permissions = getattr(
            relationship,
            "permissions",
            [],
        )

        if permissions is None:
            return []

        return [
            str(permission)
            for permission in permissions
        ]

    @staticmethod
    def _enum_value(
        value: Any,
    ) -> str:
        enum_value = getattr(
            value,
            "value",
            value,
        )

        return str(enum_value)
