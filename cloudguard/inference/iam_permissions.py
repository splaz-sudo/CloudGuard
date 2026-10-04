from fnmatch import fnmatchcase

from cloudguard.collectors.iam import IAMPolicy
from cloudguard.models.assets import CloudAsset
from cloudguard.models.relationships import (
    Relationship,
    RelationshipType,
)


class IAMPermissionEvaluator:
    """
    Converts supported IAM Allow statements into CloudGuard
    security relationships.

    This is intentionally conservative and is not yet a complete
    AWS effective-permissions simulator.
    """

    READ_ACTIONS = {
        "s3:GetObject",
        "s3:ListBucket",
        "secretsmanager:GetSecretValue",
    }

    WRITE_ACTIONS = {
        "s3:PutObject",
        "s3:DeleteObject",
    }

    def evaluate(
        self,
        principal_id: str,
        policies: list[IAMPolicy],
        assets: list[CloudAsset],
    ) -> list[Relationship]:

        relationships: list[Relationship] = []

        for policy in policies:
            for statement in policy.statements:

                if statement.effect.lower() != "allow":
                    continue

                if statement.conditions:
                    continue

                for asset in assets:
                    asset_arn = self._asset_arn(asset)

                    if asset_arn is None:
                        continue

                    if not self._resource_matches(
                        statement.resources,
                        asset_arn,
                    ):
                        continue

                    matched_actions = self._supported_actions(
                        statement.actions
                    )

                    if not matched_actions:
                        continue

                    relationships.append(
                        Relationship(
                            source=principal_id,
                            target=asset.id,
                            relationship_type=(
                                self._relationship_type(
                                    matched_actions
                                )
                            ),
                            permissions=matched_actions,
                            evidence=(
                                f"IAM policy {policy.name}"
                            ),
                        )
                    )

        return relationships

    def _supported_actions(
        self,
        patterns: list[str],
    ) -> list[str]:

        supported = self.READ_ACTIONS | self.WRITE_ACTIONS
        matched: set[str] = set()

        for pattern in patterns:
            for action in supported:
                if fnmatchcase(
                    action.lower(),
                    pattern.lower(),
                ):
                    matched.add(action)

        return sorted(matched)

    def _resource_matches(
        self,
        patterns: list[str],
        resource_arn: str,
    ) -> bool:

        return any(
            fnmatchcase(resource_arn, pattern)
            for pattern in patterns
        )

    def _relationship_type(
        self,
        actions: list[str],
    ) -> RelationshipType:

        if set(actions) & self.WRITE_ACTIONS:
            return RelationshipType.CAN_WRITE

        if set(actions) & self.READ_ACTIONS:
            return RelationshipType.CAN_READ

        return RelationshipType.CAN_ACCESS

    def _asset_arn(
        self,
        asset: CloudAsset,
    ) -> str | None:

        arn = asset.metadata.get("arn")

        if arn:
            return arn

        if asset.asset_type.value == "s3_bucket":
            return f"arn:aws:s3:::{asset.name}"

        return None
