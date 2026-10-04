from pydantic import BaseModel, Field

from cloudguard.models.relationships import (
    Relationship,
    RelationshipType,
)


class RoleAttachment(BaseModel):
    workload_id: str
    role_id: str


class PermissionGrant(BaseModel):
    principal_id: str
    target_asset_id: str
    actions: list[str] = Field(default_factory=list)


class IAMAnalyzer:
    READ_ACTIONS = {
        "s3:GetObject",
        "s3:ListBucket",
        "secretsmanager:GetSecretValue",
    }

    WRITE_ACTIONS = {
        "s3:PutObject",
        "s3:DeleteObject",
    }

    def infer_role_relationships(
        self,
        attachments: list[RoleAttachment],
    ) -> list[Relationship]:

        return [
            Relationship(
                source=attachment.workload_id,
                target=attachment.role_id,
                relationship_type=RelationshipType.ASSUMES,
                evidence=(
                    f"{attachment.workload_id} uses "
                    f"IAM role {attachment.role_id}"
                ),
            )
            for attachment in attachments
        ]

    def infer_permission_relationships(
        self,
        grants: list[PermissionGrant],
    ) -> list[Relationship]:

        relationships: list[Relationship] = []

        for grant in grants:
            actions = set(grant.actions)

            if actions & self.WRITE_ACTIONS:
                relationship_type = RelationshipType.CAN_WRITE

            elif actions & self.READ_ACTIONS:
                relationship_type = RelationshipType.CAN_READ

            else:
                relationship_type = RelationshipType.CAN_ACCESS

            relationships.append(
                Relationship(
                    source=grant.principal_id,
                    target=grant.target_asset_id,
                    relationship_type=relationship_type,
                    permissions=grant.actions,
                    evidence="Derived from IAM permission grant",
                )
            )

        return relationships
