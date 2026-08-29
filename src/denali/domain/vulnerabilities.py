"""Scanner-neutral software-component and vulnerability contracts.

Software components are durable inventory. Vulnerabilities are evaluated conditions
observed by scanners against a component in a target. Keeping these contracts separate
allows Denali to retain an SBOM and re-evaluate it as vulnerability databases change.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from denali.domain.findings import FindingSeverity, FindingState
from denali.domain.inventory import (
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    Coverage,
    CoverageState,
    Evidence,
    LifecycleState,
    RelationshipAssertion,
    RelationshipKind,
)


class ComponentScope(StrEnum):
    INSTALLED = "installed"
    DECLARED = "declared"
    EMBEDDED = "embedded"
    UNKNOWN = "unknown"


class VulnerabilityFixState(StrEnum):
    FIXED = "fixed"
    NOT_FIXED = "not_fixed"
    WONT_FIX = "wont_fix"
    UNKNOWN = "unknown"


class ExploitState(StrEnum):
    KNOWN_EXPLOITED = "known_exploited"
    PUBLIC_EXPLOIT = "public_exploit"
    NO_KNOWN_EXPLOIT = "no_known_exploit"
    UNKNOWN = "unknown"


class VulnerabilityMatchMethod(StrEnum):
    EXACT_DIRECT = "exact_direct"
    EXACT_INDIRECT = "exact_indirect"
    DISTRO = "distro"
    ECOSYSTEM = "ecosystem"
    CPE = "cpe"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class VulnerabilityScanSubject:
    """The artifact identity reported by the scanner for one run."""

    target: AssetRef
    artifact_kind: str
    artifact_locator: str
    evidence: Evidence
    artifact_digest: str | None = None

    def __post_init__(self) -> None:
        if self.target.kind is AssetKind.SOFTWARE_COMPONENT:
            raise ValueError("vulnerability scan target cannot be a software component")
        _validate_trimmed("artifact_kind", self.artifact_kind)
        _validate_trimmed("artifact_locator", self.artifact_locator)
        if self.artifact_digest is not None:
            _validate_trimmed("artifact_digest", self.artifact_digest)


@dataclass(frozen=True, slots=True)
class ComponentIdentity:
    """Stable identity of one package occurrence inside one inventory target.

    Scanner-reported filesystem locations are evidence about this occurrence. They
    are deliberately not identity: package catalogers commonly attach many files to
    one installed package.
    """

    target: AssetRef
    name: str
    version: str | None
    ecosystem: str
    package_type: str
    purl: str | None = None
    location: str | None = None

    def __post_init__(self) -> None:
        if self.target.kind is AssetKind.SOFTWARE_COMPONENT:
            raise ValueError("a software component target cannot be another component")
        for label, value in {
            "name": self.name,
            "ecosystem": self.ecosystem,
            "package_type": self.package_type,
        }.items():
            _validate_trimmed(label, value)
        for label, value in {
            "version": self.version,
            "purl": self.purl,
            "location": self.location,
        }.items():
            if value is not None:
                _validate_trimmed(label, value)
        if self.purl is not None and not self.purl.startswith("pkg:"):
            raise ValueError("component purl must start with 'pkg:'")
        if self.purl is None and self.version is None:
            raise ValueError("a component without a purl must have a version")

    @property
    def natural_key(self) -> str:
        identity: dict[str, str | None] = {
            "target": self.target.canonical_key,
        }
        if self.purl is not None:
            identity["purl"] = self.purl
        else:
            identity.update(
                {
                    "ecosystem": self.ecosystem.casefold(),
                    "package_type": self.package_type.casefold(),
                    "name": self.name,
                    "version": self.version,
                }
            )
        material = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(material.encode()).hexdigest()

    @property
    def asset_ref(self) -> AssetRef:
        return AssetRef(AssetKind.SOFTWARE_COMPONENT, self.natural_key)


@dataclass(frozen=True, slots=True)
class SoftwareComponentAssertion:
    identity: ComponentIdentity
    coverage_plane: str
    scope: ComponentScope
    assertion_type: AssertionType
    confidence: float
    evidence: Evidence
    locations: tuple[str, ...] = ()
    cpes: tuple[str, ...] = ()
    licenses: tuple[str, ...] = ()
    digests: Mapping[str, str] = field(default_factory=dict)
    attributes: Mapping[str, Any] = field(default_factory=dict)
    lifecycle: LifecycleState = LifecycleState.ACTIVE

    def __post_init__(self) -> None:
        _validate_trimmed("coverage_plane", self.coverage_plane)
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        _validate_unique_trimmed("location", self.locations)
        _validate_unique_trimmed("cpe", self.cpes)
        _validate_unique_trimmed("license", self.licenses)
        normalized_digests: dict[str, str] = {}
        for algorithm, digest in dict(self.digests).items():
            _validate_trimmed("digest algorithm", algorithm)
            _validate_trimmed("digest", digest)
            normalized_digests[algorithm.casefold()] = digest.casefold()
        object.__setattr__(self, "digests", MappingProxyType(normalized_digests))
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))

    def asset_assertion(self) -> AssetAssertion:
        identity = self.identity
        canonical = {
            **dict(self.attributes),
            "component": {
                "name": identity.name,
                "version": identity.version,
                "ecosystem": identity.ecosystem,
                "package_type": identity.package_type,
                "purl": identity.purl,
                "location": identity.location,
                "locations": list(self.locations),
                "scope": self.scope.value,
                "cpes": list(self.cpes),
                "licenses": list(self.licenses),
                "digests": dict(self.digests),
                "target": {
                    "kind": identity.target.kind.value,
                    "natural_key": identity.target.natural_key,
                },
            },
        }
        return AssetAssertion(
            asset=identity.asset_ref,
            coverage_plane=self.coverage_plane,
            display_name=(
                f"{identity.name} {identity.version}" if identity.version else identity.name
            ),
            assertion_type=self.assertion_type,
            confidence=self.confidence,
            evidence=self.evidence,
            attributes=canonical,
            lifecycle=self.lifecycle,
        )

    def containment_assertion(self) -> RelationshipAssertion:
        return RelationshipAssertion(
            source=self.identity.target,
            target=self.identity.asset_ref,
            coverage_plane=self.coverage_plane,
            kind=RelationshipKind.CONTAINS_COMPONENT,
            assertion_type=self.assertion_type,
            confidence=self.confidence,
            evidence=self.evidence,
            attributes={
                "scope": self.scope.value,
                "location": self.identity.location,
                "locations": list(self.locations),
            },
        )


@dataclass(frozen=True, slots=True)
class VulnerabilityAssertion:
    source_uid: str
    vulnerability_id: str
    component: AssetRef
    target: AssetRef
    severity: FindingSeverity
    state: FindingState
    observed_at: datetime
    evidence: Evidence
    match_method: VulnerabilityMatchMethod
    match_confidence: float
    aliases: tuple[str, ...] = ()
    title: str | None = None
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    fix_state: VulnerabilityFixState = VulnerabilityFixState.UNKNOWN
    fixed_versions: tuple[str, ...] = ()
    exploit_state: ExploitState = ExploitState.UNKNOWN
    database_version: str | None = None
    database_built_at: datetime | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_trimmed("source_uid", self.source_uid)
        _validate_trimmed("vulnerability_id", self.vulnerability_id)
        if self.component.kind is not AssetKind.SOFTWARE_COMPONENT:
            raise ValueError("vulnerability component must reference a software component")
        if self.target.kind is AssetKind.SOFTWARE_COMPONENT:
            raise ValueError("vulnerability target cannot be a software component")
        if self.observed_at.tzinfo is None:
            raise ValueError("vulnerability observed_at must be timezone-aware")
        if self.evidence.observed_at != self.observed_at:
            raise ValueError("vulnerability and evidence observation times must match")
        if not 0.0 <= self.match_confidence <= 1.0:
            raise ValueError("match_confidence must be between 0.0 and 1.0")
        if self.cvss_score is not None and not 0.0 <= self.cvss_score <= 10.0:
            raise ValueError("cvss_score must be between 0.0 and 10.0")
        if self.database_built_at is not None and self.database_built_at.tzinfo is None:
            raise ValueError("database_built_at must be timezone-aware")
        _validate_unique_trimmed("alias", self.aliases)
        _validate_unique_trimmed("fixed version", self.fixed_versions)
        for label, value in {
            "title": self.title,
            "cvss_vector": self.cvss_vector,
            "database_version": self.database_version,
        }.items():
            if value is not None:
                _validate_trimmed(label, value)
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))

    @property
    def canonical_key(self) -> str:
        material = json.dumps(
            {
                "vulnerability_id": self.vulnerability_id.upper(),
                "component": self.component.canonical_key,
                "target": self.target.canonical_key,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(material.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class VulnerabilityBatch:
    connector_id: str
    connection_id: str
    run_id: str
    scope_key: str
    collected_at: datetime
    coverage: tuple[Coverage, ...]
    vulnerabilities: tuple[VulnerabilityAssertion, ...] = ()
    scan_subject: VulnerabilityScanSubject | None = None
    authoritative: bool = False

    def __post_init__(self) -> None:
        for label, value in {
            "connector_id": self.connector_id,
            "connection_id": self.connection_id,
            "run_id": self.run_id,
            "scope_key": self.scope_key,
        }.items():
            _validate_trimmed(label, value)
        if self.collected_at.tzinfo is None:
            raise ValueError("collected_at must be timezone-aware")
        if not self.coverage:
            raise ValueError("vulnerability batches must state coverage")
        if self.scan_subject is not None:
            if self.scan_subject.evidence.observed_at != self.collected_at:
                raise ValueError("scan subject and batch collection times must match")
            if any(item.target != self.scan_subject.target for item in self.vulnerabilities):
                raise ValueError("all vulnerabilities must share the scan subject target")
        source_uids = [item.source_uid for item in self.vulnerabilities]
        if len(source_uids) != len(set(source_uids)):
            raise ValueError("one vulnerability batch cannot repeat a source_uid")

    @property
    def may_resolve_missing(self) -> bool:
        return self.authoritative and all(
            item.state is CoverageState.COMPLETE for item in self.coverage
        )


def _validate_trimmed(label: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{label} must be a non-empty trimmed string")


def _validate_unique_trimmed(label: str, values: tuple[str, ...]) -> None:
    for value in values:
        _validate_trimmed(label, value)
    if len(values) != len(set(values)):
        raise ValueError(f"{label} values must be unique")
