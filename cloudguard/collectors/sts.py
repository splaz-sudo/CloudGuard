import time

from pydantic import BaseModel

from cloudguard.aws_errors import CollectorResult
from cloudguard.collectors.aws_session import AWSSession
from cloudguard.retry import RetryConfig, retry_with_backoff


class AWSIdentity(BaseModel):
    account_id: str
    arn: str
    user_id: str


class STSCollector:
    """Retrieves the identity associated with the active AWS credentials."""

    def __init__(
        self,
        aws_session: AWSSession,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.client = aws_session.client("sts")
        self.retry_config = retry_config or RetryConfig.standard()

    def get_identity(self) -> CollectorResult:
        """
        Returns a CollectorResult with the identity data
        stored in the error_message field as JSON when successful,
        or as an error when failed.
        """

        def _collect() -> AWSIdentity:
            response = self.client.get_caller_identity()

            return AWSIdentity(
                account_id=response["Account"],
                arn=response["Arn"],
                user_id=response["UserId"],
            )

        started = time.perf_counter()

        try:
            identity = retry_with_backoff(_collect, self.retry_config)
            return CollectorResult(
                collector="sts",
                service="sts",
                region=None,
                status="success",
                resources_discovered=1,
                duration_ms=round(
                    (time.perf_counter() - started)
                    * 1000,
                    2,
                ),
                data=[identity],
            )
        except Exception as error:
            from cloudguard.aws_errors import (
                classify_collector_error,
                safe_error_message,
            )
            return CollectorResult(
                collector="sts",
                service="sts",
                region=None,
                status="failed",
                error_category=classify_collector_error(
                    error
                ),
                error_message=safe_error_message(error),
                duration_ms=round(
                    (time.perf_counter() - started)
                    * 1000,
                    2,
                ),
            )
