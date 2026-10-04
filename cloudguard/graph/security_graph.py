import networkx as nx

from cloudguard.models.assets import CloudAsset
from cloudguard.models.relationships import (
    Relationship,
    RelationshipType,
)


# When several statements produce a
# relationship between the same pair of
# assets, the stronger access type wins.
_TYPE_PRECEDENCE = {
    RelationshipType.CAN_WRITE: 3,
    RelationshipType.CAN_READ: 2,
    RelationshipType.CAN_ACCESS: 1,
}


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

        if self.graph.has_edge(
            relationship.source,
            relationship.target,
        ):
            relationship = self._merge(
                self.graph.edges[
                    relationship.source,
                    relationship.target,
                ]["relationship"],
                relationship,
            )

        self.graph.add_edge(
            relationship.source,
            relationship.target,
            relationship=relationship,
        )

    @staticmethod
    def _merge(
        existing: Relationship,
        incoming: Relationship,
    ) -> Relationship:
        """
        Merge two relationships between the
        same assets: union of observed
        permissions, combined evidence, and the
        stronger relationship type.
        """

        existing_rank = _TYPE_PRECEDENCE.get(
            existing.relationship_type, 0
        )
        incoming_rank = _TYPE_PRECEDENCE.get(
            incoming.relationship_type, 0
        )

        relationship_type = (
            incoming.relationship_type
            if incoming_rank > existing_rank
            else existing.relationship_type
        )

        permissions = sorted(
            set(existing.permissions)
            | set(incoming.permissions)
        )

        evidence_parts: list[str] = []

        for evidence in (
            existing.evidence,
            incoming.evidence,
        ):
            if (
                evidence
                and evidence
                not in evidence_parts
            ):
                evidence_parts.append(evidence)

        return Relationship(
            source=existing.source,
            target=existing.target,
            relationship_type=(
                relationship_type
            ),
            permissions=permissions,
            evidence=(
                "; ".join(evidence_parts)
                or None
            ),
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

