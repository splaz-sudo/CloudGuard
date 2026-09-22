from pydantic import BaseModel

from cloudguard.collectors.aws_session import AWSSession


class AWSIdentity(BaseModel):
    account_id: str
    arn: str
    user_id: str


class STSCollector:
    """Retrieves the identity associated with the active AWS credentials."""

    def __init__(self, aws_session: AWSSession) -> None:
        self.client = aws_session.client("sts")

    def get_identity(self) -> AWSIdentity:
        response = self.client.get_caller_identity()

        return AWSIdentity(
            account_id=response["Account"],
            arn=response["Arn"],
            user_id=response["UserId"],
        )
