from datetime import UTC, datetime

from denali.domain import (
    CorrelationAsset,
    CorrelationFinding,
    CorrelationRelationship,
    CorrelationSnapshot,
    CoverageState,
    FindingSeverity,
)
from denali.issues.engine import evaluate_agent_sensitive_write


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
