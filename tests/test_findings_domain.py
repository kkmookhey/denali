from datetime import UTC, datetime

import pytest

from denali.domain import (
    Coverage,
    CoverageState,
    EvaluationResult,
    Evidence,
    FindingAssertion,
    FindingBatch,
    FindingSeverity,
    FindingState,
)


def finding(uid: str = "finding-1") -> FindingAssertion:
    now = datetime.now(UTC)
    return FindingAssertion(
        source_uid=uid,
        rule_uid="rule-1",
        title="A security condition",
        description=None,
        risk=None,
        remediation=None,
        remediation_references=(),
        severity=FindingSeverity.HIGH,
        state=FindingState.OPEN,
        evaluation_result=EvaluationResult.FAIL,
        class_uid=2004,
        class_name="Detection Finding",
        observed_at=now,
        evidence=Evidence("test", f"test://{uid}", now),
    )


def batch(*, authoritative: bool, state: CoverageState) -> FindingBatch:
    return FindingBatch(
        connector_id="test.findings",
        connection_id="test-connection",
        run_id="run-1",
        scope_key="scope-1",
        collected_at=datetime.now(UTC),
        coverage=(Coverage("findings", state, "scope-1"),),
        findings=(finding(),),
        authoritative=authoritative,
    )


def test_only_complete_authoritative_batches_may_resolve_missing_findings() -> None:
    assert batch(authoritative=True, state=CoverageState.COMPLETE).may_resolve_missing
    assert not batch(authoritative=False, state=CoverageState.COMPLETE).may_resolve_missing
    assert not batch(authoritative=True, state=CoverageState.PARTIAL).may_resolve_missing


def test_duplicate_source_identity_is_rejected() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="repeat a source_uid"):
        FindingBatch(
            connector_id="test.findings",
            connection_id="test-connection",
            run_id="run-1",
            scope_key="scope-1",
            collected_at=now,
            coverage=(Coverage("findings", CoverageState.COMPLETE, "scope-1"),),
            findings=(finding(), finding()),
        )
