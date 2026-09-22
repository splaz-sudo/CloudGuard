import boto3
from botocore.config import Config
from boto3.session import Session


class AWSSession:
    """Creates and manages the read-only AWS SDK session used by CloudGuard."""

    def __init__(
        self,
        profile_name: str | None = None,
        region_name: str | None = None,
    ) -> None:
        self.profile_name = profile_name
        self.region_name = region_name

        self.session = boto3.Session(
            profile_name=profile_name,
            region_name=region_name,
        )

        self.config = Config(
            retries={
                "max_attempts": 3,
                "mode": "standard",
            },
        )

    def client(self, service_name: str):
        return self.session.client(
            service_name,
            config=self.config,
        )

    @property
    def region(self) -> str | None:
        return self.session.region_name
