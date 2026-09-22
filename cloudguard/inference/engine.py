from cloudguard.inference.iam import (
    IAMAnalyzer,
    PermissionGrant,
    RoleAttachment,
)
from cloudguard.inference.network import (
    NetworkConfiguration,
    NetworkExposureAnalyzer,
)
from cloudguard.models.relationships import Relationship


class SecurityInferenceEngine:
    def __init__(self) -> None:
        self.network = NetworkExposureAnalyzer()
        self.iam = IAMAnalyzer()

    def infer(
        self,
        network_configurations: list[NetworkConfiguration],
        role_attachments: list[RoleAttachment],
        permission_grants: list[PermissionGrant],
    ) -> list[Relationship]:

        relationships: list[Relationship] = []

        relationships.extend(
            self.network.infer_relationships(
                network_configurations
            )
        )

        relationships.extend(
            self.iam.infer_role_relationships(
                role_attachments
            )
        )

        relationships.extend(
            self.iam.infer_permission_relationships(
                permission_grants
            )
        )

        return relationships
