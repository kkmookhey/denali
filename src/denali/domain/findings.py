"""Provider-neutral security finding contracts.

Findings describe evaluated conditions. They may refer to inventory, but a finding is
not authority to create an asset or relationship. Source reconciliation therefore uses
the producer's finding identity and keeps affected resource references separate.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from denali.domain.inventory import Coverage, CoverageState, Evidence


class FindingSeverity(StrEnum):
    UNKNOWN = "unknown"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingState(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    UNKNOWN = "unknown"


class EvaluationResult(StrEnum):
    FAIL = "fail"
    PASS = "pass"
    MANUAL = "manual"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class AffectedResource:
    uid: str
    name: str | None = None
    resource_type: str | None = None
    provider: str | None = None
    account_uid: str | None = None
    region: str | None = None

    def __post_init__(self) -> None:
        if not self.uid.strip() or self.uid != self.uid.strip():
            raise ValueError("affected resource uid must be non-empty and trimmed")


@dataclass(frozen=True, slots=True)
class FindingAssertion:
    source_uid: str
    rule_uid: str
    title: str
    description: str | None
    risk: str | None
    remediation: str | None
    remediation_references: tuple[str, ...]
    severity: FindingSeverity
    state: FindingState
    evaluation_result: EvaluationResult
    class_uid: int
    class_name: str
    observed_at: datetime
    evidence: Evidence
    affected_resources: tuple[AffectedResource, ...] = ()
    compliance: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for label, value in {
            "source_uid": self.source_uid,
            "rule_uid": self.rule_uid,
            "title": self.title,
            "class_name": self.class_name,
        }.items():
            if not value.strip() or value != value.strip():
                raise ValueError(f"finding {label} must be non-empty and trimmed")
        if not 2_000 < self.class_uid < 3_000:
            raise ValueError("finding class_uid must be in the OCSF Findings category")
        if self.observed_at.tzinfo is None:
            raise ValueError("finding observed_at must be timezone-aware")
        if self.evidence.observed_at != self.observed_at:
            raise ValueError("finding and evidence observation times must match")
        if len({resource.uid for resource in self.affected_resources}) != len(
            self.affected_resources
        ):
            raise ValueError("a finding cannot repeat an affected resource uid")
        normalized_compliance: dict[str, tuple[str, ...]] = {}
        for framework, values in dict(self.compliance).items():
            if (
                not isinstance(framework, str)
                or not framework.strip()
                or framework != framework.strip()
            ):
                raise ValueError("compliance framework must be a non-empty trimmed string")
            controls = tuple(values)
            if any(
                not isinstance(control, str) or not control.strip() or control != control.strip()
                for control in controls
            ):
                raise ValueError("compliance controls must be non-empty trimmed strings")
            if len(set(controls)) != len(controls):
                raise ValueError("a finding cannot repeat a compliance control")
            normalized_compliance[framework] = controls
        object.__setattr__(
            self,
            "compliance",
            MappingProxyType(normalized_compliance),
        )
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class FindingBatch:
    connector_id: str
    connection_id: str
    run_id: str
    scope_key: str
    collected_at: datetime
    coverage: tuple[Coverage, ...]
    findings: tuple[FindingAssertion, ...] = ()
    authoritative: bool = False

    def __post_init__(self) -> None:
        for label, value in {
            "connector_id": self.connector_id,
            "connection_id": self.connection_id,
            "run_id": self.run_id,
            "scope_key": self.scope_key,
        }.items():
            if not value.strip():
                raise ValueError(f"{label} must be non-empty")
        if self.collected_at.tzinfo is None:
            raise ValueError("collected_at must be timezone-aware")
        if not self.coverage:
            raise ValueError("finding batches must state coverage")
        source_uids = [finding.source_uid for finding in self.findings]
        if len(set(source_uids)) != len(source_uids):
            raise ValueError("one finding batch cannot repeat a source_uid")

    @property
    def may_resolve_missing(self) -> bool:
        return self.authoritative and all(
            item.state is CoverageState.COMPLETE for item in self.coverage
        )
