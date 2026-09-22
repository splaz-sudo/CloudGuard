import networkx as nx

from cloudguard.models.assets import CloudAsset
from cloudguard.models.relationships import Relationship


class SecurityGraph:
    """Directed graph representing cloud assets and security relationships."""

    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def add_asset(self, asset: CloudAsset) -> None:
        self.graph.add_node(
            asset.id,
            asset=asset,
        )

    def add_relationship(self, relationship: Relationship) -> None:
        if relationship.source not in self.graph:
            raise ValueError(
                f"Source asset '{relationship.source}' does not exist."
            )

        if relationship.target not in self.graph:
            raise ValueError(
                f"Target asset '{relationship.target}' does not exist."
            )

        self.graph.add_edge(
            relationship.source,
            relationship.target,
            relationship=relationship,
        )

    def build(
        self,
        assets: list[CloudAsset],
        relationships: list[Relationship],
    ) -> None:
        self.graph.clear()

        for asset in assets:
            self.add_asset(asset)

        for relationship in relationships:
            self.add_relationship(relationship)

    def get_asset(self, asset_id: str) -> CloudAsset | None:
        if asset_id not in self.graph:
            return None

        return self.graph.nodes[asset_id]["asset"]

    def get_relationship(
        self,
        source: str,
        target: str,
    ) -> Relationship | None:
        if not self.graph.has_edge(source, target):
            return None

        return self.graph.edges[source, target]["relationship"]

    def successors(self, asset_id: str) -> list[CloudAsset]:
        if asset_id not in self.graph:
            return []

        return [
            self.graph.nodes[node_id]["asset"]
            for node_id in self.graph.successors(asset_id)
        ]

    @property
    def asset_count(self) -> int:
        return self.graph.number_of_nodes()

    @property
    def relationship_count(self) -> int:
        return self.graph.number_of_edges()

