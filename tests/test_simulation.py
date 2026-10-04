import pytest

from cloudguard.remediation.service import (
    RemediationNotFoundError,
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


def snapshot_state(result):
    graph = result.security_graph

    relationships = []

    for source, target in graph.graph.edges:
        relationship = graph.get_relationship(
            source,
            target,
        )

        relationships.append(
            relationship.model_dump()
        )

    return {
        "assets": [
            asset.model_dump()
            for asset in result.assets
        ],
        "relationships": sorted(
            item["relationship_id"]
            for item in relationships
        ),
        "attack_paths": [
            path.model_dump()
            for path in result.attack_paths
        ],
        "findings": [
            finding.model_dump()
            for finding in result.findings
        ],
    }


def simulate_local_lab_exposure_fix(
    service,
    analysis,
):
    return service.simulate(
        analysis,
        "REM-RESTRICT-NETWORK-EXPOSURE-"
        "i-cloudguard-web-01",
    )


def test_simulation_removes_internet_path(
    service,
    local_lab_analysis,
):
    result = (
        simulate_local_lab_exposure_fix(
            service,
            local_lab_analysis,
        )
    )

    assert result.before.attack_paths == 1
    assert result.after.attack_paths == 0

    assert result.impact.paths_removed == 1

    removed_path_id = (
        local_lab_analysis
        .attack_paths[0]
        .path_id
    )

    assert (
        result.impact.removed_path_ids
        == [removed_path_id]
    )


def test_simulation_recalculates_risk(
    service,
    local_lab_analysis,
):
    result = (
        simulate_local_lab_exposure_fix(
            service,
            local_lab_analysis,
        )
    )

    assert result.before.highest_risk == 95
    assert result.before.findings == 2

    assert result.after.highest_risk == 0
    assert result.after.findings == 0

    assert (
        result.impact.risk_reduction
        == result.before.highest_risk
        - result.after.highest_risk
    )

    assert (
        result.impact
        .risk_reduction_percent
        == 100.0
    )

    assert result.simulation_only is True
    assert result.note


def test_simulated_risk_is_calculated_not_zeroed(
    service,
    build_analysis,
):
    """
    Fixing one of two public exposures must
    leave the second exposure's finding (and
    its score) intact.
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

    analysis = build_analysis(
        instances=[
            make_instance(
                "i-web-a",
                [group_a.group_id],
                profile_arn=profile.arn,
            ),
            make_instance(
                "i-web-b",
                [group_b.group_id],
            ),
        ],
        security_groups=[group_a, group_b],
        buckets=[bucket],
        roles=[role],
        instance_profiles=[profile],
    )

    result = service.simulate(
        analysis,
        "REM-RESTRICT-NETWORK-EXPOSURE-"
        "i-web-a",
    )

    assert result.before.highest_risk == 95
    assert result.before.attack_paths == 1

    assert result.after.attack_paths == 0

    # i-web-b remains internet-exposed, so its
    # network finding (80) must survive.
    assert result.after.highest_risk == 80
    assert result.after.findings == 1

    assert result.impact.risk_reduction == 15
    assert (
        result.impact
        .risk_reduction_percent
        == round(15 / 95 * 100, 1)
    )


def test_simulated_iam_fix_keeps_network_finding(
    service,
    build_analysis,
):
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

    analysis = build_analysis(
        instances=[
            make_instance(
                "i-web",
                [group.group_id],
                profile_arn=profile.arn,
            )
        ],
        security_groups=[group],
        buckets=[bucket],
        roles=[role],
        instance_profiles=[profile],
    )

    result = service.simulate(
        analysis,
        "REM-REDUCE-IAM-PERMISSION-"
        "iam-role:writer-role-"
        "s3:customer-backups",
    )

    assert result.before.attack_paths == 1
    assert result.after.attack_paths == 0

    # The workload stays public, so the
    # exposure finding (80) must survive.
    assert result.after.highest_risk == 80
    assert result.impact.risk_reduction == 15


def test_simulation_does_not_mutate_original_state(
    service,
    local_lab_analysis,
):
    before = snapshot_state(
        local_lab_analysis
    )

    simulate_local_lab_exposure_fix(
        service,
        local_lab_analysis,
    )

    after = snapshot_state(
        local_lab_analysis
    )

    assert before == after


def test_repeated_simulations_are_isolated(
    service,
    local_lab_analysis,
):
    baseline = snapshot_state(
        local_lab_analysis
    )

    first = (
        simulate_local_lab_exposure_fix(
            service,
            local_lab_analysis,
        )
    )

    assert snapshot_state(
        local_lab_analysis
    ) == baseline

    second = (
        simulate_local_lab_exposure_fix(
            service,
            local_lab_analysis,
        )
    )

    assert snapshot_state(
        local_lab_analysis
    ) == baseline

    # Simulation B starts from the original
    # state, not from simulation A's result.
    assert (
        second.before
        == first.before
    )
    assert (
        second.after
        == first.after
    )


def test_unknown_remediation_raises(
    service,
    local_lab_analysis,
):
    with pytest.raises(
        RemediationNotFoundError
    ):
        service.simulate(
            local_lab_analysis,
            "REM-DOES-NOT-EXIST",
        )
