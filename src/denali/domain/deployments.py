"""Provider-neutral deployment identity contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class IdentifierComparison(StrEnum):
    """Comparison permitted for one independently observed deployment identifier."""

    EXACT = "exact"
    PREFIX = "prefix"


@dataclass(frozen=True, slots=True)
class DeploymentIdentifier:
    """One scoped identifier used to join source intent to a runtime observation."""

    name: str
    value: str
    comparison: IdentifierComparison = IdentifierComparison.EXACT
    evidence_basis: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("deployment identifier name is required")
        if not self.value.strip():
            raise ValueError("deployment identifier value is required")

    def matches(self, observed: DeploymentIdentifier) -> bool:
        if self.name != observed.name:
            return False
        if self.comparison is IdentifierComparison.EXACT:
            return self.value == observed.value
        return observed.value.startswith(self.value)

    def to_record(self) -> dict[str, str]:
        record = {
            "name": self.name,
            "value": self.value,
            "comparison": self.comparison.value,
        }
        if self.evidence_basis:
            record["evidence_basis"] = self.evidence_basis
        return record

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> DeploymentIdentifier:
        return cls(
            name=str(record["name"]),
            value=str(record["value"]),
            comparison=IdentifierComparison(str(record.get("comparison", "exact"))),
            evidence_basis=(
                str(record["evidence_basis"]) if record.get("evidence_basis") else None
            ),
        )


@dataclass(frozen=True, slots=True)
class DeploymentIdentity:
    """Provider/runtime boundary plus the identifiers required inside that boundary."""

    provider: str
    runtime_kind: str
    identifiers: tuple[DeploymentIdentifier, ...]

    def __post_init__(self) -> None:
        if not self.provider.strip():
            raise ValueError("deployment provider is required")
        if not self.runtime_kind.strip():
            raise ValueError("deployment runtime kind is required")
        if not self.identifiers:
            raise ValueError("at least one deployment identifier is required")

    def matches(self, observed: DeploymentIdentity) -> bool:
        """Return true only when the boundary and every required identifier agree."""

        if self.provider != observed.provider or self.runtime_kind != observed.runtime_kind:
            return False
        return all(
            any(required.matches(candidate) for candidate in observed.identifiers)
            for required in self.identifiers
        )

    def match_basis(self) -> list[str]:
        return [
            item.evidence_basis or f"{item.comparison.value}_{item.name}"
            for item in self.identifiers
        ]

    def values(self, name: str) -> tuple[str, ...]:
        return tuple(item.value for item in self.identifiers if item.name == name)

    def to_record(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "runtime_kind": self.runtime_kind,
            "identifiers": [item.to_record() for item in self.identifiers],
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> DeploymentIdentity:
        identifiers = record.get("identifiers")
        if not isinstance(identifiers, list):
            raise ValueError("deployment identity identifiers must be a list")
        return cls(
            provider=str(record["provider"]),
            runtime_kind=str(record["runtime_kind"]),
            identifiers=tuple(
                DeploymentIdentifier.from_record(item)
                for item in identifiers
                if isinstance(item, dict)
            ),
        )
