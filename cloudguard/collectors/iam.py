from pydantic import BaseModel, Field

from cloudguard.collectors.aws_session import AWSSession


class IAMRole(BaseModel):
    name: str
    arn: str
    role_id: str
    attached_policies: list[str] = Field(default_factory=list)


class IAMUser(BaseModel):
    name: str
    arn: str
    user_id: str
    attached_policies: list[str] = Field(default_factory=list)


class IAMCollector:
    def __init__(self, aws_session: AWSSession) -> None:
        self.client = aws_session.client("iam")

    def collect_roles(self) -> list[IAMRole]:
        roles: list[IAMRole] = []

        paginator = self.client.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page.get("Roles", []):
                policies = self._role_policies(role["RoleName"])

                roles.append(
                    IAMRole(
                        name=role["RoleName"],
                        arn=role["Arn"],
                        role_id=role["RoleId"],
                        attached_policies=policies,
                    )
                )

        return roles

    def collect_users(self) -> list[IAMUser]:
        users: list[IAMUser] = []

        paginator = self.client.get_paginator("list_users")

        for page in paginator.paginate():
            for user in page.get("Users", []):
                policies = self._user_policies(user["UserName"])

                users.append(
                    IAMUser(
                        name=user["UserName"],
                        arn=user["Arn"],
                        user_id=user["UserId"],
                        attached_policies=policies,
                    )
                )

        return users

    def _role_policies(self, role_name: str) -> list[str]:
        policies: list[str] = []

        paginator = self.client.get_paginator(
            "list_attached_role_policies"
        )

        for page in paginator.paginate(RoleName=role_name):
            policies.extend(
                policy["PolicyArn"]
                for policy in page.get("AttachedPolicies", [])
            )

        return policies

    def _user_policies(self, user_name: str) -> list[str]:
        policies: list[str] = []

        paginator = self.client.get_paginator(
            "list_attached_user_policies"
        )

        for page in paginator.paginate(UserName=user_name):
            policies.extend(
                policy["PolicyArn"]
                for policy in page.get("AttachedPolicies", [])
            )

        return policies
