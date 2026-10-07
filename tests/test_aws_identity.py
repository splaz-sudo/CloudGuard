"""
Real-AWS identity handling.

STSCollector.get_identity() never raises: it reports failure through a
CollectorResult. These tests lock in that every consumer turns that result
into either a real account identity or a credential-safe failure -- never an
unbound name, an AttributeError, or a fabricated account id.

No network and no AWS credentials are used: every AWS client is a local fake.
"""

import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from cloudguard.aws_errors import CollectorResult
from cloudguard.config import Settings
from cloudguard.persistence.database import Database
from cloudguard.persistence.repository import ScanRepository
from cloudguard.scans.models import ScanSource, ScanStatus
from cloudguard.scans.service import ScanService
from cloudguard.collectors.sts import (
    AWSIdentity,
    STSCollector,
    require_identity,
)

ACCOUNT = "123456789012"


class FakeSTSClient:
    def __init__(self, error=None):
        self.error = error
        self.calls = 0

    def get_caller_identity(self):
        self.calls += 1
        if self.error:
            raise self.error
        return {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/auditor",
            "UserId": "AIDAEXAMPLE",
        }


class FakeAWSSession:
    """Stand-in for cloudguard.collectors.aws_session.AWSSession."""

    sts = FakeSTSClient()
    region = "us-east-1"

    def __init__(self, *args, **kwargs):
        pass

    def client(self, name):
        assert name == "sts", "only STS should be created in these tests"
        return type(self).sts


def _collector(error=None) -> STSCollector:
    session = FakeAWSSession()
    FakeAWSSession.sts = FakeSTSClient(error)
    return STSCollector(session)


# --------------------------------------------------
# STSCollector / require_identity
# --------------------------------------------------


def test_get_identity_success_returns_identity():
    result = _collector().get_identity()

    assert result.status == "success"
    assert isinstance(result.data[0], AWSIdentity)
    assert result.data[0].account_id == ACCOUNT

    identity = require_identity(result)
    assert identity.account_id == ACCOUNT
    assert identity.arn.endswith("user/auditor")


def test_get_identity_missing_credentials_is_a_failed_result_not_a_raise():
    result = _collector(NoCredentialsError()).get_identity()

    assert result.status == "failed"
    assert result.data == []
    assert "credentials" in result.error_message.lower()


def test_get_identity_access_denied_is_safe():
    error = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "AKIASECRETKEY denied"}},
        "GetCallerIdentity",
    )
    result = _collector(error).get_identity()

    assert result.status == "failed"
    assert "AKIASECRETKEY" not in (result.error_message or "")


def test_require_identity_raises_safe_error_and_never_fabricates():
    result = _collector(NoCredentialsError()).get_identity()

    with pytest.raises(RuntimeError) as exc:
        require_identity(result)

    assert "identity check failed" in str(exc.value).lower()
    assert ACCOUNT not in str(exc.value)


def test_require_identity_rejects_empty_success():
    empty = CollectorResult(
        collector="sts", service="sts", region=None, status="success"
    )

    with pytest.raises(RuntimeError):
        require_identity(empty)


# --------------------------------------------------
# Full real-AWS scan path (_analyze_aws), all AWS faked
# --------------------------------------------------


def _service() -> ScanService:
    return ScanService(
        ScanRepository(Database(":memory:")),
        Settings(environment="test", database_path=":memory:"),
    )


def _empty_ok(collector):
    return CollectorResult(
        collector=collector, service=collector, region="us-east-1",
        status="success",
    )


@pytest.fixture()
def fake_aws(monkeypatch):
    import cloudguard.collectors.aws_session as aws_session
    import cloudguard.collectors.ec2 as ec2
    import cloudguard.collectors.iam as iam
    import cloudguard.collectors.s3 as s3

    monkeypatch.setattr(aws_session, "AWSSession", FakeAWSSession)

    # Collectors are faked at the method level: empty-but-successful, so the
    # test exercises identity wiring without any AWS client calls.
    for cls, names in (
        (ec2.EC2Collector, ("collect_instances", "collect_security_groups")),
        (s3.S3Collector, ("collect_buckets",)),
        (iam.IAMCollector,
         ("collect_roles", "collect_users", "collect_instance_profiles")),
    ):
        monkeypatch.setattr(cls, "__init__", lambda self, *a, **k: None)
        for name in names:
            monkeypatch.setattr(
                cls, name,
                lambda self, _n=name: _empty_ok(_n),
            )


def test_aws_scan_fails_cleanly_when_sts_fails(fake_aws):
    FakeAWSSession.sts = FakeSTSClient(NoCredentialsError())

    record = _service().create_scan(ScanSource.AWS, wait=True)

    assert record.status == ScanStatus.FAILED
    assert "identity check failed" in (record.error_message or "").lower()
    assert "NameError" not in (record.error_message or "")
    assert record.account_identifier in (None, "")


def test_aws_scan_uses_real_sts_account_identity(fake_aws):
    FakeAWSSession.sts = FakeSTSClient()

    record = _service().create_scan(ScanSource.AWS, wait=True)

    assert record.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
    assert record.account_identifier == ACCOUNT
    assert FakeAWSSession.sts.calls >= 1
