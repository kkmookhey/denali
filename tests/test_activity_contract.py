from datetime import UTC, datetime

import pytest

from denali.domain import (
    ActivityBatch,
    ActivityCategory,
    ActivityCorrelation,
    ActivityEntity,
    ActivityEntityRole,
    ActivityOutcome,
    ActivityRecord,
    AssetKind,
    AssetRef,
    Coverage,
    CoverageState,
    Evidence,
)

NOW = datetime(2026, 8, 27, tzinfo=UTC)


def _record(*entities: ActivityEntity) -> ActivityRecord:
    return ActivityRecord(
        source_uid="event-1",
        category=ActivityCategory.MODEL_INVOCATION,
        activity_name="aws.bedrock.Converse",
        title="Model invoked",
        occurred_at=NOW,
        observed_at=NOW,
        outcome=ActivityOutcome.SUCCESS,
        provider="aws_bedrock",
        evidence=Evidence("cloudtrail", "s3://evidence/event-1", NOW),
        entities=entities,
    )


def test_activity_keeps_exact_inventory_link_explicit() -> None:
    model = ActivityEntity(
        ActivityEntityRole.MODEL,
        "model-1",
        "Model 1",
        AssetRef(AssetKind.AI_MODEL, "aws:bedrock:model:model-1"),
        ActivityCorrelation.EXACT_IDENTIFIER,
        1.0,
    )
    assert _record(model).entities[0].asset == model.asset


def test_unresolved_event_reference_cannot_claim_confidence() -> None:
    with pytest.raises(ValueError, match="unlinked"):
        ActivityEntity(
            ActivityEntityRole.APPLICATION,
            "app-1",
            correlation=ActivityCorrelation.EXACT_IDENTIFIER,
            confidence=1.0,
        )


def test_batch_rejects_duplicate_source_events() -> None:
    with pytest.raises(ValueError, match="repeat a source_uid"):
        ActivityBatch(
            "connector",
            "connection",
            "run",
            "scope",
            NOW,
            (Coverage("runtime_activity", CoverageState.COMPLETE, "scope"),),
            (_record(), _record()),
        )
