import networkx as nx
from pydantic import BaseModel

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

            results.append(
                AttackPath(
                    source=source,
                    target=target,
                    nodes=node_path,
                    hop_count=len(node_path) - 1,
                    sensitive_target=bool(
                        target_asset and target_asset.sensitive
                    ),
                    relationships=relationships,
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
