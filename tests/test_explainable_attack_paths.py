from cloudguard.models.relationships import (
    RelationshipType,
)


def get_local_lab_path(local_lab_analysis):
    paths = local_lab_analysis.attack_paths

    assert len(paths) == 1

    return paths[0]


def test_attack_path_has_stable_id(
    local_lab_analysis,
    analysis_service,
):
    path = get_local_lab_path(
        local_lab_analysis
    )

    assert path.path_id
    assert path.path_id.startswith("PATH-")

    second_run = (
        analysis_service
        .analyze_local_lab()
    )

    assert (
        second_run.attack_paths[0].path_id
        == path.path_id
    )


def test_attack_path_has_severity_and_score(
    local_lab_analysis,
):
    path = get_local_lab_path(
        local_lab_analysis
    )

    assert path.severity == "CRITICAL"
    assert path.risk_score == 95


def test_attack_path_exposes_every_hop(
    local_lab_analysis,
):
    path = get_local_lab_path(
        local_lab_analysis
    )

    assert len(path.hops) == path.hop_count
    assert len(path.hops) == 3


def test_hop_reasons_match_relationships(
    local_lab_analysis,
):
    path = get_local_lab_path(
        local_lab_analysis
    )

    (
        exposure_hop,
        role_hop,
        permission_hop,
    ) = path.hops

    assert (
        exposure_hop.relationship_type
        == RelationshipType.EXPOSED_TO
    )

    assert "security-group" in (
        exposure_hop.reason.lower()
    )

    assert (
        role_hop.relationship_type
        == RelationshipType.ASSUMES
    )

    assert "instance profile" in (
        role_hop.reason.lower()
    )

    assert (
        permission_hop.relationship_type
        == RelationshipType.CAN_READ
    )

    assert "s3:GetObject" in (
        permission_hop.reason
    )


def test_hop_evidence_is_preserved(
    local_lab_analysis,
):
    path = get_local_lab_path(
        local_lab_analysis
    )

    for hop, relationship in zip(
        path.hops,
        path.relationships,
    ):
        assert hop.evidence == (
            relationship.evidence
        )

        assert hop.permissions == (
            relationship.permissions
        )


def test_exposure_hop_names_responsible_security_group(
    local_lab_analysis,
):
    path = get_local_lab_path(
        local_lab_analysis
    )

    exposure_hop = path.hops[0]

    assert exposure_hop.configuration
    assert "sg-cloudguard-web" in (
        exposure_hop.configuration
    )


def test_every_hop_has_impact(
    local_lab_analysis,
):
    path = get_local_lab_path(
        local_lab_analysis
    )

    for hop in path.hops:
        assert hop.impact


def test_path_has_human_explanation(
    local_lab_analysis,
):
    path = get_local_lab_path(
        local_lab_analysis
    )

    assert "sensitive" in path.explanation
    assert "internet" in (
        path.explanation.lower()
    )
