"""Postgres contract tests.

Set ``DENALI_TEST_DSN`` to run them. The local Compose DSN uses port 55450; a skip
is expected in the dependency-free unit target and is not accepted in the DB gate.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from denali.domain import (
    AffectedResource,
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    Coverage,
    CoverageState,
    EvaluationResult,
    Evidence,
    FindingAssertion,
    FindingBatch,
    FindingSeverity,
    FindingState,
    InventoryBatch,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


def assertion(key: str, observed_at: datetime) -> AssetAssertion:
    return AssetAssertion(
        asset=AssetRef(AssetKind.AI_AGENT, key),
        coverage_plane="agents",
        display_name=key,
        assertion_type=AssertionType.EXTERNALLY_VERIFIED,
        confidence=1.0,
        evidence=Evidence("fixture", f"fixture://{key}", observed_at),
    )


def inventory_batch(
    *, run_id: str, state: CoverageState, assets: tuple[AssetAssertion, ...], at: datetime
) -> InventoryBatch:
    return InventoryBatch(
        connector_id="fixture",
        connection_id="fixture-connection",
        run_id=run_id,
        scope_key="fixture-scope",
        collected_at=at,
        coverage=(Coverage("agents", state, "fixture-scope"),),
        assets=assets,
    )


def finding_assertion(
    observed_at: datetime,
    *,
    state: FindingState = FindingState.OPEN,
    result: EvaluationResult = EvaluationResult.FAIL,
) -> FindingAssertion:
    return FindingAssertion(
        source_uid="prowler-finding-1",
        rule_uid="bedrock_guardrail_prompt_attack",
        title="Guardrail prompt attack filter is not enabled",
        description="The attached guardrail does not enable the expected filter.",
        risk="Prompt manipulation may change model behavior.",
        remediation="Enable the prompt attack filter.",
        remediation_references=("https://docs.aws.amazon.com/bedrock/",),
        severity=FindingSeverity.HIGH,
        state=state,
        evaluation_result=result,
        class_uid=2004,
        class_name="Detection Finding",
        observed_at=observed_at,
        evidence=Evidence("ocsf_finding", "file:///report#item=0", observed_at),
        affected_resources=(
            AffectedResource(
                uid="arn:aws:bedrock:us-east-1:123456789012:guardrail/gr-1",
                name="customer-safety",
                resource_type="AwsBedrockGuardrail",
                provider="aws",
                account_uid="123456789012",
                region="us-east-1",
            ),
        ),
        compliance={"OWASP-LLM": ("LLM01",)},
    )


def findings_batch(
    *,
    run_id: str,
    at: datetime,
    state: CoverageState,
    findings: tuple[FindingAssertion, ...],
    authoritative: bool = False,
) -> FindingBatch:
    return FindingBatch(
        connector_id="denali.ocsf_findings",
        connection_id="prowler-aws-test",
        run_id=run_id,
        scope_key="provider=aws,account=123456789012",
        collected_at=at,
        coverage=(
            Coverage(
                "ocsf_findings",
                state,
                "provider=aws,account=123456789012",
            ),
        ),
        findings=findings,
        authoritative=authoritative,
    )


@pytest.fixture
def repository():
    assert DSN
    migrate(DSN)
    tenant = str(uuid.uuid4())
    return tenant, PostgresInventoryRepository(DSN)


def test_complete_empty_snapshot_withdraws_but_partial_does_not(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    first = assertion("agent-one", now)
    repo.ingest(
        tenant,
        inventory_batch(run_id="run-1", state=CoverageState.COMPLETE, assets=(first,), at=now),
    )

    partial = repo.ingest(
        tenant,
        inventory_batch(
            run_id="run-2",
            state=CoverageState.PARTIAL,
            assets=(),
            at=now + timedelta(minutes=1),
        ),
    )
    assert partial["withdrawn_assets"] == 0
    assert repo.summary(tenant)["total"] == 1

    complete = repo.ingest(
        tenant,
        inventory_batch(
            run_id="run-3",
            state=CoverageState.COMPLETE,
            assets=(),
            at=now + timedelta(minutes=2),
        ),
    )
    assert complete["withdrawn_assets"] == 1
    assert repo.summary(tenant)["total"] == 0


def test_one_source_cannot_withdraw_another_sources_asset(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    shared = assertion("shared-agent", now)
    repo.ingest(
        tenant,
        inventory_batch(
            run_id="fixture-run", state=CoverageState.COMPLETE, assets=(shared,), at=now
        ),
    )
    second_source = InventoryBatch(
        connector_id="other-source",
        connection_id="other-connection",
        run_id="other-run",
        scope_key="fixture-scope",
        collected_at=now,
        coverage=(Coverage("agents", CoverageState.COMPLETE, "fixture-scope"),),
        assets=(shared,),
    )
    repo.ingest(tenant, second_source)

    repo.ingest(
        tenant,
        inventory_batch(
            run_id="fixture-empty",
            state=CoverageState.COMPLETE,
            assets=(),
            at=now + timedelta(minutes=1),
        ),
    )
    assert repo.summary(tenant)["total"] == 1
    detail = repo.get_asset(tenant, str(repo.list_assets(tenant)[0]["id"]))
    assert detail is not None
    active = [row for row in detail["assertions"] if row["withdrawn_at"] is None]
    assert {row["connector_id"] for row in active} == {"other-source"}


def test_findings_do_not_mint_assets_and_partial_absence_does_not_resolve(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    finding = finding_assertion(now)
    repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="finding-run-1",
            at=now,
            state=CoverageState.COMPLETE,
            findings=(finding,),
        ),
    )

    assert repo.summary(tenant)["total"] == 0
    rows = repo.list_findings(tenant)
    assert len(rows) == 1
    assert rows[0]["state"] == "open"
    detail = repo.get_finding(tenant, str(rows[0]["id"]))
    assert detail is not None
    assert detail["resources"][0]["uid"].endswith("guardrail/gr-1")
    assert detail["compliance"] == {"OWASP-LLM": ["LLM01"]}

    result = repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="finding-run-partial",
            at=now + timedelta(minutes=1),
            state=CoverageState.PARTIAL,
            findings=(),
            authoritative=True,
        ),
    )
    assert result["resolved_missing"] == 0
    assert repo.list_findings(tenant)[0]["state"] == "open"


def test_authoritative_absence_and_explicit_pass_resolve_findings(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="finding-run-open",
            at=now,
            state=CoverageState.COMPLETE,
            findings=(finding_assertion(now),),
        ),
    )

    absent = repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="finding-run-empty",
            at=now + timedelta(minutes=1),
            state=CoverageState.COMPLETE,
            findings=(),
            authoritative=True,
        ),
    )
    assert absent["resolved_missing"] == 1
    assert repo.list_findings(tenant)[0]["resolution_reason"] == (
        "absent_from_authoritative_snapshot"
    )

    repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="finding-run-reopen",
            at=now + timedelta(minutes=2),
            state=CoverageState.COMPLETE,
            findings=(finding_assertion(now + timedelta(minutes=2)),),
        ),
    )
    passed = finding_assertion(
        now + timedelta(minutes=3),
        state=FindingState.RESOLVED,
        result=EvaluationResult.PASS,
    )
    repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="finding-run-pass",
            at=now + timedelta(minutes=3),
            state=CoverageState.COMPLETE,
            findings=(passed,),
        ),
    )
    rows = repo.list_findings(tenant)
    assert rows[0]["state"] == "resolved"
    assert rows[0]["resolution_reason"] == "source_status"
    detail = repo.get_finding(tenant, str(rows[0]["id"]))
    assert detail is not None
    assert len(detail["observations"]) == 3


def test_pass_without_a_prior_failure_does_not_create_finding_noise(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    passed = finding_assertion(
        now,
        state=FindingState.RESOLVED,
        result=EvaluationResult.PASS,
    )

    result = repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="pass-only-run",
            at=now,
            state=CoverageState.COMPLETE,
            findings=(passed,),
        ),
    )

    assert result == {"findings": 0, "resolved_missing": 0}
    assert repo.finding_summary(tenant)["total"] == 0


def test_reobservation_time_does_not_look_like_a_semantic_finding_change(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="stable-run-1",
            at=now,
            state=CoverageState.COMPLETE,
            findings=(finding_assertion(now),),
        ),
    )
    first_changed_at = repo.list_findings(tenant)[0]["last_changed_at"]

    later = now + timedelta(minutes=5)
    repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="stable-run-2",
            at=later,
            state=CoverageState.COMPLETE,
            findings=(finding_assertion(later),),
        ),
    )

    assert repo.list_findings(tenant)[0]["last_changed_at"] == first_changed_at
