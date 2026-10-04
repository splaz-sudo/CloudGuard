import pytest

from cloudguard.remediation.models import (
    RemediationActionType,
)
from cloudguard.remediation.service import (
    RemediationService,
)
from tests.conftest import (
    make_bucket,
    make_instance,
    make_open_security_group,
    make_profile,
    make_role,
)


@pytest.fixture()
def service():
    return RemediationService()


@pytest.fixture()
def write_env_analysis(build_analysis):
    """
    Public EC2 whose role has write permissions
    on a sensitive bucket.
    """

    bucket = make_bucket()
    role = make_role(
        "writer-role",
        ["s3:PutObject", "s3:DeleteObject"],
        bucket.name,
    )
    profile = make_profile(
        "writer-profile",
        [role.name],
    )
    group = make_open_security_group("sg-web")
    instance = make_instance(
        "i-web",
        [group.group_id],
        profile_arn=profile.arn,
    )

    return build_analysis(
        instances=[instance],
        security_groups=[group],
        buckets=[bucket],
        roles=[role],
        instance_profiles=[profile],
    )


@pytest.fixture()
def two_exposure_analysis(build_analysis):
    """
    Two public instances. Only i-web-a sits on
    an attack path to a sensitive resource.
    """

    bucket = make_bucket()
    role = make_role(
        "reader-role",
        ["s3:GetObject"],
        bucket.name,
    )
    profile = make_profile(
        "reader-profile",
        [role.name],
    )

    group_a = make_open_security_group(
        "sg-a",
        port=80,
    )
    group_b = make_open_security_group(
        "sg-b",
        port=22,
    )

    instance_a = make_instance(
        "i-web-a",
        [group_a.group_id],
        profile_arn=profile.arn,
    )
    instance_b = make_instance(
        "i-web-b",
        [group_b.group_id],
    )

    return build_analysis(
        instances=[instance_a, instance_b],
        security_groups=[group_a, group_b],
        buckets=[bucket],
        roles=[role],
        instance_profiles=[profile],
    )


def test_local_lab_generates_network_remediation(
    service,
    local_lab_analysis,
):
    remediations = service.get_remediations(
        local_lab_analysis
    )

    assert len(remediations) == 1

    remediation = remediations[0]

    assert remediation.action_type == (
        RemediationActionType
        .RESTRICT_NETWORK_EXPOSURE
    )

    assert (
        remediation.affected_resources
        == ["i-cloudguard-web-01"]
    )


def test_network_remediation_links_evidence(
    service,
    local_lab_analysis,
):
    remediation = service.get_remediations(
        local_lab_analysis
    )[0]

    assert remediation.finding_ids == [
        "CG-NET-i-cloudguard-web-01"
    ]

    path_id = (
        local_lab_analysis
        .attack_paths[0]
        .path_id
    )

    assert (
        remediation.attack_path_ids
        == [path_id]
    )

    assert remediation.relationship_ids == [
        "internet->i-cloudguard-web-01"
        ":exposed_to"
    ]

    assert remediation.paths_affected == 1

    assert any(
        "sg-cloudguard-web" in item
        for item in remediation.evidence
    )

    assert remediation.manual_steps

    assert remediation.expected_effect


def test_remediation_ids_are_deterministic(
    service,
    analysis_service,
):
    first = service.get_remediations(
        analysis_service.analyze_local_lab()
    )
    second = service.get_remediations(
        analysis_service.analyze_local_lab()
    )

    assert [
        item.remediation_id
        for item in first
    ] == [
        item.remediation_id
        for item in second
    ]

    assert first[0].remediation_id == (
        "REM-RESTRICT-NETWORK-EXPOSURE-"
        "i-cloudguard-web-01"
    )


def test_read_only_role_generates_no_iam_remediation(
    service,
    local_lab_analysis,
):
    remediations = service.get_remediations(
        local_lab_analysis
    )

    action_types = {
        item.action_type
        for item in remediations
    }

    assert (
        RemediationActionType
        .REDUCE_IAM_PERMISSION
    ) not in action_types


def test_write_permission_generates_iam_remediation(
    service,
    write_env_analysis,
):
    remediations = service.get_remediations(
        write_env_analysis
    )

    iam_remediations = [
        item
        for item in remediations
        if item.action_type
        == RemediationActionType
        .REDUCE_IAM_PERMISSION
    ]

    assert len(iam_remediations) == 1

    remediation = iam_remediations[0]

    assert set(
        remediation.affected_resources
    ) == {
        "iam-role:writer-role",
        "s3:customer-backups",
    }

    assert remediation.paths_affected == 1

    assert any(
        "s3:PutObject" in item
        for item in remediation.evidence
    )


def test_private_environment_generates_nothing(
    service,
    build_analysis,
):
    group = make_open_security_group("sg-priv")

    group.inbound_rules[
        0
    ].sources = ["10.0.0.0/8"]

    instance = make_instance(
        "i-private",
        [group.group_id],
        public_ip=None,
    )

    result = build_analysis(
        instances=[instance],
        security_groups=[group],
        buckets=[make_bucket()],
        roles=[],
        instance_profiles=[],
    )

    assert (
        service.get_remediations(result)
        == []
    )


def test_prioritization_ranks_by_impact(
    service,
    two_exposure_analysis,
):
    prioritized = (
        service.get_prioritized(
            two_exposure_analysis
        )
    )

    assert len(prioritized) == 2

    first, second = prioritized

    assert first.priority == 1
    assert second.priority == 2

    assert (
        "i-web-a"
        in first.affected_resources
    )

    assert first.paths_removed == 1
    assert first.risk_before == 95
    assert first.risk_after == 80
    assert first.risk_reduction == 15

    assert second.paths_removed == 0
    assert second.risk_after == 95
    assert second.risk_reduction == 0


def test_prioritization_is_deterministic(
    service,
    two_exposure_analysis,
):
    first_run = service.get_prioritized(
        two_exposure_analysis
    )
    second_run = service.get_prioritized(
        two_exposure_analysis
    )

    assert [
        item.remediation_id
        for item in first_run
    ] == [
        item.remediation_id
        for item in second_run
    ]
