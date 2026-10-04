from cloudguard.collectors.ec2 import (
    EC2Instance,
    SecurityGroup,
)
from cloudguard.collectors.iam import (
    IAMRole,
    InstanceProfile,
)
from cloudguard.graph.security_graph import SecurityGraph
from cloudguard.inference.iam_permissions import (
    IAMPermissionEvaluator,
)
from cloudguard.inference.network import (
    InboundRule,
    NetworkConfiguration,
    NetworkExposureAnalyzer,
)
from cloudguard.models.assets import AssetType, CloudAsset
from cloudguard.models.relationships import (
    Relationship,
    RelationshipType,
)


class AWSGraphBuilder:
    """
    Builds CloudGuard's security graph from normalized AWS
    assets and AWS collector data.

    Current relationships:
        Internet -> EC2
        EC2 -> IAM Role
        IAM Role -> AWS Resource
    """

    def __init__(self) -> None:
        self.network_analyzer = NetworkExposureAnalyzer()
        self.iam_evaluator = IAMPermissionEvaluator()

    def build(
        self,
        assets: list[CloudAsset],
        instances: list[EC2Instance],
        security_groups: list[SecurityGroup],
        roles: list[IAMRole],
        instance_profiles: list[InstanceProfile],
    ) -> SecurityGraph:

        graph = SecurityGraph()

        all_assets = list(assets)

        if not any(
            asset.id == "internet"
            for asset in all_assets
        ):
            all_assets.append(
                CloudAsset(
                    id="internet",
                    name="Internet",
                    asset_type=AssetType.INTERNET,
                )
            )

        relationships: list[Relationship] = []

        relationships.extend(
            self._network_relationships(
                instances,
                security_groups,
            )
        )

        relationships.extend(
            self._role_relationships(
                instances,
                roles,
                instance_profiles,
            )
        )

        relationships.extend(
            self._permission_relationships(
                roles,
                all_assets,
            )
        )

        graph.build(
            assets=all_assets,
            relationships=relationships,
        )

        return graph

    def _network_relationships(
        self,
        instances: list[EC2Instance],
        security_groups: list[SecurityGroup],
    ) -> list[Relationship]:

        groups_by_id = {
            group.group_id: group
            for group in security_groups
        }

        configurations: list[NetworkConfiguration] = []

        for instance in instances:
            inbound_rules: list[InboundRule] = []

            for group_id in instance.security_group_ids:
                group = groups_by_id.get(group_id)

                if group is None:
                    continue

                for rule in group.inbound_rules:
                    inbound_rules.append(
                        InboundRule(
                            protocol=rule.protocol,
                            from_port=rule.from_port,
                            to_port=rule.to_port,
                            sources=rule.sources,
                            security_group_id=(
                                group.group_id
                            ),
                            security_group_name=(
                                group.group_name
                            ),
                        )
                    )

            configurations.append(
                NetworkConfiguration(
                    asset_id=instance.instance_id,
                    public_ip=instance.public_ip,
                    inbound_rules=inbound_rules,
                )
            )

        return self.network_analyzer.infer_relationships(
            configurations
        )

    def _role_relationships(
        self,
        instances: list[EC2Instance],
        roles: list[IAMRole],
        instance_profiles: list[InstanceProfile],
    ) -> list[Relationship]:

        relationships: list[Relationship] = []

        profiles_by_arn = {
            profile.arn: profile
            for profile in instance_profiles
        }

        roles_by_name = {
            role.name: role
            for role in roles
        }

        for instance in instances:
            profile_arn = (
                instance.iam_instance_profile_arn
            )

            if not profile_arn:
                continue

            profile = profiles_by_arn.get(
                profile_arn
            )

            if profile is None:
                continue

            for role_name in profile.role_names:
                role = roles_by_name.get(
                    role_name
                )

                if role is None:
                    continue

                relationships.append(
                    Relationship(
                        source=instance.instance_id,
                        target=(
                            f"iam-role:{role.name}"
                        ),
                        relationship_type=(
                            RelationshipType.ASSUMES
                        ),
                        evidence=(
                            f"EC2 instance "
                            f"{instance.instance_id} "
                            f"uses instance profile "
                            f"{profile.name}, which "
                            f"contains IAM role "
                            f"{role.name}"
                        ),
                    )
                )

        return relationships

    def _permission_relationships(
        self,
        roles: list[IAMRole],
        assets: list[CloudAsset],
    ) -> list[Relationship]:

        relationships: list[Relationship] = []

        for role in roles:
            relationships.extend(
                self.iam_evaluator.evaluate(
                    principal_id=(
                        f"iam-role:{role.name}"
                    ),
                    policies=role.attached_policies,
                    assets=assets,
                )
            )

        return relationships
