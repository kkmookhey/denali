from datetime import UTC, datetime, timedelta

from denali.domain import (
    CorrelationAsset,
    CorrelationFinding,
    CorrelationRelationship,
    CorrelationRuntimeDetection,
    CorrelationSnapshot,
    CoverageState,
    DetectionActivity,
    DetectionActivityEntity,
    FindingSeverity,
)
from denali.issues.engine import (
    aggregate_issue_evaluation_state,
    evaluate_agent_sensitive_write,
    evaluate_unreviewed_ai_consent_then_use,
)


def asset(
    identifier: str,
    kind: str,
    key: str,
    *,
    assertion_type: str = "externally_verified",
    **attributes,
) -> CorrelationAsset:
    return CorrelationAsset(
        id=identifier,
        kind=kind,
        natural_key=key,
        display_name=key,
        assertion_type=assertion_type,
        confidence=1.0,
        attributes=attributes,
    )


def relationship(
    identifier: str,
    source: str,
    target: str,
    kind: str,
    *,
    assertion_type: str = "externally_verified",
) -> CorrelationRelationship:
    return CorrelationRelationship(
        id=identifier,
        source_id=source,
        target_id=target,
        kind=kind,
        category="capability",
        assertion_type=assertion_type,
        confidence=1.0,
    )


def finding(identifier: str, signal: str, uid: str) -> CorrelationFinding:
    return CorrelationFinding(
        id=identifier,
        source_uid=identifier,
        rule_uid=f"rule-{identifier}",
        title=identifier,
        severity=FindingSeverity.HIGH,
        state="open",
        evaluation_result="fail",
        resource_uids=(uid,),
        attributes={"denali_signal": signal},
    )


def snapshot(
    *,
    write_assertion: str = "externally_verified",
    include_write: bool = True,
    tool_assertion: str = "externally_verified",
):
    assets = (
        asset("agent", "ai_agent", "agent-key"),
        asset("identity", "identity", "identity-key"),
        asset("tool", "ai_tool", "tool-key", assertion_type=tool_assertion),
        asset("data", "ai_datastore", "data-key", classification="sensitive"),
    )
    relationships = [
        relationship("runs", "agent", "identity", "runs_as"),
        relationship("invokes", "agent", "tool", "can_invoke"),
    ]
    if include_write:
        relationships.append(
            relationship(
                "writes",
                "tool",
                "data",
                "can_write",
                assertion_type=write_assertion,
            )
        )
    return CorrelationSnapshot(
        assets=assets,
        relationships=tuple(relationships),
        findings=(
            finding("identity-finding", "identity.overprivileged", "identity-key"),
            finding("tool-finding", "tool.write_without_confirmation", "tool-key"),
        ),
    )


def test_confirmed_issue_requires_two_findings_and_three_independent_edges() -> None:
    evaluation = evaluate_agent_sensitive_write(snapshot(), evaluated_at=datetime.now(UTC))

    assert evaluation.state is CoverageState.COMPLETE
    assert len(evaluation.candidates) == 1
    issue = evaluation.candidates[0]
    assert {item.finding_id for item in issue.findings} == {
        "identity-finding",
        "tool-finding",
    }
    assert [item.relationship_id for item in issue.path_edges] == [
        "runs",
        "invokes",
        "writes",
    ]
    assert issue.attributes["path_status"] == "confirmed"


def test_empty_unknown_rule_does_not_downgrade_a_completed_rule() -> None:
    now = datetime.now(UTC)
    complete = evaluate_agent_sensitive_write(snapshot(), evaluated_at=now)
    unavailable = evaluate_unreviewed_ai_consent_then_use(
        (), (), (), coverage_state=CoverageState.UNKNOWN, evaluated_at=now
    )

    assert unavailable.candidates == ()
    assert aggregate_issue_evaluation_state((complete, unavailable)) is CoverageState.COMPLETE


def test_incomplete_unknown_rule_remains_visible_in_aggregate_coverage() -> None:
    now = datetime.now(UTC)
    complete = evaluate_agent_sensitive_write(snapshot(), evaluated_at=now)
    incomplete = evaluate_agent_sensitive_write(
        snapshot(include_write=False), evaluated_at=now
    )

    assert incomplete.incomplete_candidates == 1
    assert aggregate_issue_evaluation_state((complete, incomplete)) is CoverageState.UNKNOWN


def test_finding_resource_references_do_not_manufacture_a_missing_edge() -> None:
    evaluation = evaluate_agent_sensitive_write(
        snapshot(include_write=False), evaluated_at=datetime.now(UTC)
    )

    assert evaluation.candidates == ()
    assert evaluation.state is CoverageState.UNKNOWN
    assert evaluation.incomplete_candidates == 1


def test_inferred_capability_is_not_treated_as_a_confirmed_path() -> None:
    evaluation = evaluate_agent_sensitive_write(
        snapshot(write_assertion="inferred"), evaluated_at=datetime.now(UTC)
    )

    assert evaluation.candidates == ()
    assert evaluation.state is CoverageState.UNKNOWN


def test_inferred_inventory_node_is_not_treated_as_a_confirmed_path() -> None:
    evaluation = evaluate_agent_sensitive_write(
        snapshot(tool_assertion="inferred"), evaluated_at=datetime.now(UTC)
    )

    assert evaluation.candidates == ()
    assert evaluation.state is CoverageState.UNKNOWN


def test_unreviewed_high_impact_consent_followed_by_exact_use_confirms_issue() -> None:
    consent_at = datetime(2026, 8, 16, 21, 15, tzinfo=UTC)
    application = asset(
        "application",
        "ai_application",
        "entra:tenant:application:claude",
        governance_status="unreviewed",
    )
    detection = CorrelationRuntimeDetection(
        id="consent-detection",
        rule_uid="DENALI-RUNTIME-ENTRA-CONSENT-001",
        title="Consent changed",
        severity=FindingSeverity.HIGH,
        state="open",
        confidence=1.0,
        first_seen_at=consent_at,
        last_seen_at=consent_at,
        activity_ids=("consent-event",),
        asset_ids=(application.id,),
        attributes={"high_impact_scopes": ["Mail.ReadWrite"]},
    )
    sign_in = DetectionActivity(
        id="sign-in-event",
        category="ai_app_sign_in",
        outcome="success",
        title="Claude sign-in succeeded",
        occurred_at=consent_at + timedelta(minutes=1),
        entities=(
            DetectionActivityEntity(
                role="actor",
                external_uid="user-id",
                display_name="user@example.com",
            ),
            DetectionActivityEntity(
                role="application",
                external_uid=application.natural_key,
                asset_id=application.id,
            ),
        ),
    )

    evaluation = evaluate_unreviewed_ai_consent_then_use(
        (detection,), (sign_in,), (application,), evaluated_at=consent_at
    )

    assert evaluation.state is CoverageState.COMPLETE
    assert len(evaluation.candidates) == 1
    issue = evaluation.candidates[0]
    assert issue.detections[0].detection_id == detection.id
    assert issue.activities[0].activity_id == sign_in.id
    assert issue.path_nodes[0].asset_id == application.id
    assert issue.attributes["actors"] == ["user@example.com"]


def test_consent_then_use_requires_strictly_later_exact_activity() -> None:
    consent_at = datetime(2026, 8, 16, 21, 15, tzinfo=UTC)
    application = asset(
        "application",
        "ai_application",
        "entra:tenant:application:claude",
        governance_status="unreviewed",
    )
    detection = CorrelationRuntimeDetection(
        id="consent-detection",
        rule_uid="DENALI-RUNTIME-ENTRA-CONSENT-001",
        title="Consent changed",
        severity=FindingSeverity.HIGH,
        state="open",
        confidence=1.0,
        first_seen_at=consent_at,
        last_seen_at=consent_at,
        activity_ids=("consent-event",),
        asset_ids=(application.id,),
        attributes={"high_impact_scopes": ["Mail.ReadWrite"]},
    )
    simultaneous = DetectionActivity(
        id="sign-in-event",
        category="ai_app_sign_in",
        outcome="success",
        title="Claude sign-in succeeded",
        occurred_at=consent_at,
        entities=(
            DetectionActivityEntity(
                role="application",
                external_uid=application.natural_key,
                asset_id=application.id,
            ),
        ),
    )

    evaluation = evaluate_unreviewed_ai_consent_then_use(
        (detection,), (simultaneous,), (application,), evaluated_at=consent_at
    )

    assert evaluation.candidates == ()


def test_consent_then_use_never_assumes_missing_governance_is_unreviewed() -> None:
    consent_at = datetime(2026, 8, 16, 21, 15, tzinfo=UTC)
    application = asset(
        "application",
        "ai_application",
        "entra:tenant:application:claude",
    )
    detection = CorrelationRuntimeDetection(
        id="consent-detection",
        rule_uid="DENALI-RUNTIME-ENTRA-CONSENT-001",
        title="Consent changed",
        severity=FindingSeverity.HIGH,
        state="open",
        confidence=1.0,
        first_seen_at=consent_at,
        last_seen_at=consent_at,
        activity_ids=("consent-event",),
        asset_ids=(application.id,),
        attributes={"high_impact_scopes": ["Mail.ReadWrite"]},
    )
    sign_in = DetectionActivity(
        id="sign-in-event",
        category="ai_app_sign_in",
        outcome="success",
        title="Claude sign-in succeeded",
        occurred_at=consent_at + timedelta(minutes=1),
        entities=(
            DetectionActivityEntity(
                role="application",
                external_uid=application.natural_key,
                asset_id=application.id,
            ),
        ),
    )

    evaluation = evaluate_unreviewed_ai_consent_then_use(
        (detection,), (sign_in,), (application,), evaluated_at=consent_at
    )

    assert evaluation.candidates == ()
    assert evaluation.state is CoverageState.UNKNOWN
