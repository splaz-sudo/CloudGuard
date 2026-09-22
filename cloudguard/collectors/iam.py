from typing import Any

from pydantic import BaseModel, Field

from cloudguard.collectors.aws_session import AWSSession


class IAMPolicyStatement(BaseModel):
    effect: str
    actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    conditions: dict[str, Any] = Field(default_factory=dict)


class IAMPolicy(BaseModel):
    name: str
    arn: str
    statements: list[IAMPolicyStatement] = Field(
        default_factory=list
    )


class IAMRole(BaseModel):
    name: str
    arn: str
    role_id: str
    attached_policies: list[IAMPolicy] = Field(
        default_factory=list
    )


class IAMUser(BaseModel):
    name: str
    arn: str
    user_id: str
    attached_policies: list[IAMPolicy] = Field(
        default_factory=list
    )


class InstanceProfile(BaseModel):
    name: str
    arn: str
    role_names: list[str] = Field(default_factory=list)


class IAMCollector:
    def __init__(
        self,
        aws_session: AWSSession,
    ) -> None:
        self.client = aws_session.client("iam")

    @staticmethod
    def _as_list(
        value: str | list[str] | None,
    ) -> list[str]:
        if value is None:
            return []

        if isinstance(value, list):
            return value

        return [value]

    def _load_policy(
        self,
        policy_name: str,
        policy_arn: str,
    ) -> IAMPolicy:
        response = self.client.get_policy(
            PolicyArn=policy_arn
        )

        policy = response["Policy"]

        version_id = policy["DefaultVersionId"]

        version_response = self.client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id,
        )

        document = version_response[
            "PolicyVersion"
        ]["Document"]

        statements = document.get(
            "Statement",
            [],
        )

        if isinstance(statements, dict):
            statements = [statements]

        parsed_statements: list[
            IAMPolicyStatement
        ] = []

        for statement in statements:
            parsed_statements.append(
                IAMPolicyStatement(
                    effect=statement.get(
                        "Effect",
                        "",
                    ),
                    actions=self._as_list(
                        statement.get("Action")
                    ),
                    resources=self._as_list(
                        statement.get("Resource")
                    ),
                    conditions=statement.get(
                        "Condition",
                        {},
                    ),
                )
            )

        return IAMPolicy(
            name=policy_name,
            arn=policy_arn,
            statements=parsed_statements,
        )

    def _attached_role_policies(
        self,
        role_name: str,
    ) -> list[IAMPolicy]:
        policies: list[IAMPolicy] = []

        paginator = self.client.get_paginator(
            "list_attached_role_policies"
        )

        for page in paginator.paginate(
            RoleName=role_name
        ):
            for policy in page.get(
                "AttachedPolicies",
                [],
            ):
                policies.append(
                    self._load_policy(
                        policy_name=policy[
                            "PolicyName"
                        ],
                        policy_arn=policy[
                            "PolicyArn"
                        ],
                    )
                )

        return policies

    def _attached_user_policies(
        self,
        user_name: str,
    ) -> list[IAMPolicy]:
        policies: list[IAMPolicy] = []

        paginator = self.client.get_paginator(
            "list_attached_user_policies"
        )

        for page in paginator.paginate(
            UserName=user_name
        ):
            for policy in page.get(
                "AttachedPolicies",
                [],
            ):
                policies.append(
                    self._load_policy(
                        policy_name=policy[
                            "PolicyName"
                        ],
                        policy_arn=policy[
                            "PolicyArn"
                        ],
                    )
                )

        return policies

    def collect_roles(
        self,
    ) -> list[IAMRole]:
        roles: list[IAMRole] = []

        paginator = self.client.get_paginator(
            "list_roles"
        )

        for page in paginator.paginate():
            for role in page.get(
                "Roles",
                [],
            ):
                roles.append(
                    IAMRole(
                        name=role["RoleName"],
                        arn=role["Arn"],
                        role_id=role["RoleId"],
                        attached_policies=(
                            self._attached_role_policies(
                                role["RoleName"]
                            )
                        ),
                    )
                )

        return roles

    def collect_users(
        self,
    ) -> list[IAMUser]:
        users: list[IAMUser] = []

        paginator = self.client.get_paginator(
            "list_users"
        )

        for page in paginator.paginate():
            for user in page.get(
                "Users",
                [],
            ):
                users.append(
                    IAMUser(
                        name=user["UserName"],
                        arn=user["Arn"],
                        user_id=user["UserId"],
                        attached_policies=(
                            self._attached_user_policies(
                                user["UserName"]
                            )
                        ),
                    )
                )

        return users

    def collect_instance_profiles(
        self,
    ) -> list[InstanceProfile]:
        profiles: list[InstanceProfile] = []

        paginator = self.client.get_paginator(
            "list_instance_profiles"
        )

        for page in paginator.paginate():
            for profile in page.get(
                "InstanceProfiles",
                [],
            ):
                profiles.append(
                    InstanceProfile(
                        name=profile[
                            "InstanceProfileName"
                        ],
                        arn=profile["Arn"],
                        role_names=[
                            role["RoleName"]
                            for role in profile.get(
                                "Roles",
                                [],
                            )
                        ],
                    )
                )

        return profiles
