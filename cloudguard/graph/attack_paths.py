import hashlib

import networkx as nx
from pydantic import BaseModel, Field

from cloudguard.findings.scoring import (
    ATTACK_PATH_TO_SENSITIVE_SCORE,
    severity_from_score,
)
from cloudguard.graph.explanations import (
    AttackPathHop,
    explain_hop,
    explain_path_summary,
)
from cloudguard.graph.security_graph import SecurityGraph
from cloudguard.models.assets import CloudAsset
from cloudguard.models.relationships import Relationship


class AttackPath(BaseModel):
    source: str
    target: str
    nodes: list[str]
    hop_count: int
    sensitive_target: bool
    relationships: list[Relationship]

    path_id: str = ""
    severity: str = "INFO"
    risk_score: int = 0
    hops: list[AttackPathHop] = Field(
        default_factory=list
    )
    explanation: str = ""


class AttackPathEngine:
    """Discovers security-relevant paths through the cloud graph."""

    def __init__(self, security_graph: SecurityGraph) -> None:
        self.security_graph = security_graph

    def find_paths(
        self,
        source: str,
        target: str,
        max_depth: int = 8,
    ) -> list[AttackPath]:

        graph = self.security_graph.graph

        if source not in graph or target not in graph:
            return []

        raw_paths = nx.all_simple_paths(
            graph,
            source=source,
            target=target,
            cutoff=max_depth,
        )

        results: list[AttackPath] = []

        for node_path in raw_paths:
            relationships: list[Relationship] = []

            for index in range(len(node_path) - 1):
                relationship = self.security_graph.get_relationship(
                    node_path[index],
                    node_path[index + 1],
                )

                if relationship is not None:
                    relationships.append(relationship)

            target_asset = self.security_graph.get_asset(target)

            sensitive_target = bool(
                target_asset and target_asset.sensitive
            )

            results.append(
                AttackPath(
                    source=source,
                    target=target,
                    nodes=node_path,
                    hop_count=len(node_path) - 1,
                    sensitive_target=sensitive_target,
                    relationships=relationships,
                    path_id=_path_id(
                        node_path,
                        relationships,
                    ),
                    severity=(
                        severity_from_score(
                            ATTACK_PATH_TO_SENSITIVE_SCORE
                        )
                        if sensitive_target
                        else "INFO"
                    ),
                    risk_score=(
                        ATTACK_PATH_TO_SENSITIVE_SCORE
                        if sensitive_target
                        else 0
                    ),
                    hops=self._explain_hops(
                        node_path,
                        relationships,
                    ),
                    explanation=(
                        explain_path_summary(
                            source,
                            target,
                            len(node_path) - 1,
                            sensitive_target,
                        )
                    ),
                )
            )

        results.sort(
            key=lambda path: (
                path.target,
                path.nodes,
            )
        )

        return results

    def find_paths_to_sensitive_assets(
        self,
        source: str = "internet",
        max_depth: int = 8,
    ) -> list[AttackPath]:

        graph = self.security_graph.graph

        if source not in graph:
            return []

        results: list[AttackPath] = []

        for node_id in graph.nodes:
            asset: CloudAsset = graph.nodes[node_id]["asset"]

            if not asset.sensitive:
                continue

            results.extend(
                self.find_paths(
                    source=source,
                    target=node_id,
                    max_depth=max_depth,
                )
            )

        return results

    def _explain_hops(
        self,
        node_path: list[str],
        relationships: list[Relationship],
    ) -> list[AttackPathHop]:

        hops: list[AttackPathHop] = []

        for index, relationship in enumerate(
            relationships
        ):
            source_asset = (
                self.security_graph.get_asset(
                    node_path[index]
                )
            )

            target_asset = (
                self.security_graph.get_asset(
                    node_path[index + 1]
                )
            )

            hops.append(
                explain_hop(
                    relationship,
                    source_asset,
                    target_asset,
                )
            )

        return hops


def _path_id(
    node_path: list[str],
    relationships: list[Relationship],
) -> str:
    """
    Stable, content-derived path identity.

    Built from the ordered node identities and
    the ordered relationship types, so two
    semantically identical attack paths across
    scans receive the same identifier.
    Timestamps and enumeration order are never
    part of the identity.
    """

    parts: list[str] = []

    for index, node_id in enumerate(node_path):
        parts.append(node_id)

        if index < len(relationships):
            parts.append(
                relationships[index]
                .relationship_type
                .value
            )

    digest = hashlib.sha1(
        ">".join(parts).encode("utf-8")
    ).hexdigest()

    return f"PATH-{digest[:12]}"
