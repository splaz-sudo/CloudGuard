"""
AWS error classification for CloudGuard.

Provides a unified taxonomy for credential status
and collector execution errors. Safe error
messages are exposed to users; detailed
diagnostics remain in server logs.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CredentialStatus(str, Enum):
    """
    Classification of AWS credential state.
    """
    MISSING = "missing"
    INVALID = "invalid"
    EXPIRED = "expired"
    ACCESS_DENIED = "access_denied"
    OK = "ok"


class CollectorErrorCategory(str, Enum):
    """
    Safe, user-facing categories for collector failures.
    """
    CREDENTIALS_MISSING = "credentials_missing"
    CREDENTIALS_INVALID = "credentials_invalid"
    CREDENTIALS_EXPIRED = "credentials_expired"
    ACCESS_DENIED = "access_denied"
    NETWORK_FAILURE = "network_failure"
    SERVICE_UNAVAILABLE = "service_unavailable"
    THROTTLING = "throttling"
    REGION_UNAVAILABLE = "region_unavailable"
    UNSUPPORTED_SERVICE = "unsupported_service"
    COLLECTOR_INTERNAL_ERROR = "collector_internal_error"
    TIMEOUT = "timeout"
    VALIDATION_ERROR = "validation_error"


# Errors that are safe to retry with backoff
RETRYABLE_ERROR_CODES = frozenset({
    "RequestTimeout",
    "RequestTimeoutException",
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "RequestThrottled",
    "RequestThrottledException",
    "ServiceUnavailable",
    "ServiceUnavailableException",
    "InternalFailure",
    "InternalServerError",
    "503",
    "504",
})

# Errors that must NOT be retried
NON_RETRYABLE_ERROR_CODES = frozenset({
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthFailure",
    "InvalidClientTokenId",
    "InvalidAccessKeyId",
    "UnrecognizedClientException",
    "TokenRefreshRequired",
    "ExpiredToken",
    "ExpiredTokenException",
    "ValidationError",
    "InvalidParameterValue",
    "InvalidParameterException",
    "MalformedPolicyDocument",
    "NoSuchEntity",
    "NoSuchEntityException",
    "EntityAlreadyExists",
    "EntityAlreadyExistsException",
    "OptInRequired",
    "SubscriptionRequiredException",
})


@dataclass(frozen=True)
class CollectorResult:
    """
    Result of a single collector execution.
    """
    collector: str
    service: str
    region: str | None
    status: str  # "success" | "partial" | "failed"
    resources_discovered: int = 0
    duration_ms: float = 0.0
    error_category: CollectorErrorCategory | None = None
    error_message: str | None = None
    coverage_limitation: str | None = None
    data: list = None

    def __post_init__(self):
        if self.data is None:
            object.__setattr__(self, "data", [])


def classify_credential_error(
    error: Exception,
) -> CredentialStatus:
    """
    Classify an exception into a credential status.

    Uses the standard boto3/botocore error codes.
    """
    from botocore.exceptions import (
        NoCredentialsError,
        ClientError,
        BotoCoreError,
    )

    if isinstance(error, NoCredentialsError):
        return CredentialStatus.MISSING

    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "")
        if code in {
            "InvalidClientTokenId",
            "UnrecognizedClientException",
        }:
            return CredentialStatus.INVALID
        if code in {
            "ExpiredToken",
            "ExpiredTokenException",
            "TokenRefreshRequired",
        }:
            return CredentialStatus.EXPIRED
        if code in {
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
            "AuthFailure",
        }:
            return CredentialStatus.ACCESS_DENIED

    if isinstance(error, BotoCoreError):
        # Connection errors, DNS failures, etc.
        return CredentialStatus.ACCESS_DENIED

    return CredentialStatus.ACCESS_DENIED


def classify_collector_error(
    error: Exception,
) -> CollectorErrorCategory:
    """
    Classify an exception into a safe, user-facing
    collector error category.
    """
    from botocore.exceptions import (
        NoCredentialsError,
        ClientError,
        BotoCoreError,
        ReadTimeoutError,
        ConnectTimeoutError,
    )

    if isinstance(error, NoCredentialsError):
        return CollectorErrorCategory.CREDENTIALS_MISSING

    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "")
        http_status = error.response.get("ResponseMetadata", {}).get(
            "HTTPStatusCode", 0
        )

        if code in {
            "InvalidClientTokenId",
            "UnrecognizedClientException",
        }:
            return CollectorErrorCategory.CREDENTIALS_INVALID

        if code in {
            "ExpiredToken",
            "ExpiredTokenException",
            "TokenRefreshRequired",
        }:
            return CollectorErrorCategory.CREDENTIALS_EXPIRED

        if code in {
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
            "AuthFailure",
        }:
            return CollectorErrorCategory.ACCESS_DENIED

        if code in {
            "RequestTimeout",
            "RequestTimeoutException",
        }:
            return CollectorErrorCategory.TIMEOUT

        if code in {
            "Throttling",
            "ThrottlingException",
            "TooManyRequestsException",
            "RequestThrottled",
            "RequestThrottledException",
        }:
            return CollectorErrorCategory.THROTTLING

        if code in {
            "ServiceUnavailable",
            "ServiceUnavailableException",
            "InternalFailure",
            "InternalServerError",
        } or http_status in {502, 503, 504}:
            return CollectorErrorCategory.SERVICE_UNAVAILABLE

        if code in {
            "InvalidParameterValue",
            "InvalidParameterException",
            "ValidationError",
            "MalformedPolicyDocument",
        }:
            return CollectorErrorCategory.VALIDATION_ERROR

        if code in {
            "OptInRequired",
            "SubscriptionRequiredException",
        }:
            return CollectorErrorCategory.REGION_UNAVAILABLE

        if code in {
            "UnsupportedOperation",
            "InvalidAction",
        }:
            return CollectorErrorCategory.UNSUPPORTED_SERVICE

    if isinstance(error, (ReadTimeoutError, ConnectTimeoutError)):
        return CollectorErrorCategory.TIMEOUT

    if isinstance(error, BotoCoreError):
        # Connection errors, DNS failures, etc.
        return CollectorErrorCategory.NETWORK_FAILURE

    return CollectorErrorCategory.COLLECTOR_INTERNAL_ERROR


def is_retryable_error(
    error: Exception,
) -> bool:
    """
    Determine if an error is safe to retry with backoff.
    """
    from botocore.exceptions import ClientError

    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "")
        if code in RETRYABLE_ERROR_CODES:
            return True
        if code in NON_RETRYABLE_ERROR_CODES:
            return False

    # For other BotoCoreErrors (network issues), retry
    from botocore.exceptions import BotoCoreError
    if isinstance(error, BotoCoreError):
        return True

    return False


def safe_error_message(
    error: Exception,
) -> str:
    """
    Generate a safe, user-facing error message that
    never includes credential material.
    """
    category = classify_collector_error(error)

    messages = {
        CollectorErrorCategory.CREDENTIALS_MISSING: (
            "AWS credentials were not found. Configure a profile, "
            "environment credentials, or an IAM role."
        ),
        CollectorErrorCategory.CREDENTIALS_INVALID: (
            "AWS credentials are invalid or not recognized."
        ),
        CollectorErrorCategory.CREDENTIALS_EXPIRED: (
            "AWS credentials have expired. Refresh your session."
        ),
        CollectorErrorCategory.ACCESS_DENIED: (
            "AWS access was denied. The credentials may lack "
            "required permissions."
        ),
        CollectorErrorCategory.NETWORK_FAILURE: (
            "Network error while contacting AWS. Check connectivity."
        ),
        CollectorErrorCategory.SERVICE_UNAVAILABLE: (
            "AWS service is temporarily unavailable."
        ),
        CollectorErrorCategory.THROTTLING: (
            "AWS API rate limit exceeded. The scan will retry "
            "automatically."
        ),
        CollectorErrorCategory.REGION_UNAVAILABLE: (
            "The AWS region is not enabled or not supported."
        ),
        CollectorErrorCategory.UNSUPPORTED_SERVICE: (
            "The AWS service is not available in this region."
        ),
        CollectorErrorCategory.COLLECTOR_INTERNAL_ERROR: (
            "An internal error occurred during collection."
        ),
        CollectorErrorCategory.TIMEOUT: (
            "The AWS request timed out."
        ),
        CollectorErrorCategory.VALIDATION_ERROR: (
            "Invalid request parameters sent to AWS."
        ),
    }

    return messages.get(
        category,
        "An unexpected error occurred during AWS collection.",
    )