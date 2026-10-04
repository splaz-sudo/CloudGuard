from pydantic import BaseModel, Field

from cloudguard.models.relationships import (
    Relationship,
    RelationshipType,
)


class InboundRule(BaseModel):
    protocol: str
    from_port: int | None = None
    to_port: int | None = None
    sources: list[str] = Field(default_factory=list)

    security_group_id: str | None = None
    security_group_name: str | None = None


class NetworkConfiguration(BaseModel):
    asset_id: str
    public_ip: str | None = None
    inbound_rules: list[InboundRule] = Field(default_factory=list)


class NetworkExposureAnalyzer:
    INTERNET_CIDRS = {
        "0.0.0.0/0",
        "::/0",
    }

    def is_publicly_exposed(
        self,
        configuration: NetworkConfiguration,
    ) -> bool:
        if not configuration.public_ip:
            return False

        for rule in configuration.inbound_rules:
            if any(
                source in self.INTERNET_CIDRS
                for source in rule.sources
            ):
                return True

        return False

    def infer_relationships(
        self,
        configurations: list[NetworkConfiguration],
    ) -> list[Relationship]:

        relationships: list[Relationship] = []

        for configuration in configurations:
            if not self.is_publicly_exposed(configuration):
                continue

            exposed_rules = []

            for rule in configuration.inbound_rules:
                if any(
                    source in self.INTERNET_CIDRS
                    for source in rule.sources
                ):
                    rule_description = (
                        f"{rule.protocol}:"
                        f"{rule.from_port}-{rule.to_port}"
                    )

                    if rule.security_group_id:
                        rule_description += (
                            f" (security group "
                            f"{rule.security_group_id})"
                        )

                    exposed_rules.append(
                        rule_description
                    )

            evidence = (
                "Public IP "
                f"{configuration.public_ip}; "
                "internet-accessible inbound rules: "
                + ", ".join(exposed_rules)
            )

            relationships.append(
                Relationship(
                    source="internet",
                    target=configuration.asset_id,
                    relationship_type=RelationshipType.EXPOSED_TO,
                    evidence=evidence,
                )
            )

        return relationships
