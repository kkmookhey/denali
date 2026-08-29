from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from denali.domain import (
    AssertionType,
    AssetKind,
    AssetRef,
    ComponentIdentity,
    ComponentScope,
    Coverage,
    CoverageState,
    Evidence,
    ExploitState,
    FindingSeverity,
    FindingState,
    RelationshipKind,
    SoftwareComponentAssertion,
    VulnerabilityAssertion,
    VulnerabilityBatch,
    VulnerabilityFixState,
    VulnerabilityMatchMethod,
)

OBSERVED_AT = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
TARGET = AssetRef(AssetKind.AI_WORKLOAD, "aws:123:us-east-1:workload-1")


def evidence(source: str = "syft") -> Evidence:
    return Evidence(
        source_type=source,
        locator="file:///scan.json#component=0",
        observed_at=OBSERVED_AT,
        payload={"source": source},
    )


def component_identity() -> ComponentIdentity:
    return ComponentIdentity(
        target=TARGET,
        name="ray",
        version="2.3.1",
        ecosystem="python",
        package_type="python",
        purl="pkg:pypi/ray@2.3.1",
        location="/usr/local/lib/python3.11/site-packages/ray",
    )


def vulnerability(source_uid: str = "grype:CVE-2023-6020:ray") -> VulnerabilityAssertion:
    return VulnerabilityAssertion(
        source_uid=source_uid,
        vulnerability_id="CVE-2023-6020",
        aliases=("GHSA-xxxx-yyyy-zzzz",),
        component=component_identity().asset_ref,
        target=TARGET,
        title="Ray local file inclusion",
        description="A vulnerable Ray version is installed.",
        severity=FindingSeverity.HIGH,
        state=FindingState.OPEN,
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        fix_state=VulnerabilityFixState.FIXED,
        fixed_versions=("2.8.1",),
        exploit_state=ExploitState.PUBLIC_EXPLOIT,
        observed_at=OBSERVED_AT,
        evidence=evidence("grype"),
        match_method=VulnerabilityMatchMethod.EXACT_DIRECT,
        match_confidence=1.0,
        database_version="6.1.2",
    )


def test_component_identity_is_stable_and_location_independent() -> None:
    identity = component_identity()
    assert identity.asset_ref.kind is AssetKind.SOFTWARE_COMPONENT
    assert identity.natural_key == component_identity().natural_key
    assert replace(identity, location="/opt/app/ray").natural_key == identity.natural_key
    assert replace(identity, version="2.8.1", purl="pkg:pypi/ray@2.8.1").natural_key != (
        identity.natural_key
    )
    assert replace(
        identity,
        ecosystem="pypi",
        package_type="python-package",
        name="Ray",
        version=None,
    ).natural_key == identity.natural_key


def test_component_becomes_typed_inventory_and_containment() -> None:
    assertion = SoftwareComponentAssertion(
        identity=component_identity(),
        coverage_plane="software_components",
        scope=ComponentScope.INSTALLED,
        assertion_type=AssertionType.OBSERVED,
        confidence=1.0,
        evidence=evidence(),
        locations=("/usr/local/lib/python3.11/site-packages/ray",),
        cpes=("cpe:2.3:a:ray_project:ray:2.3.1:*:*:*:*:*:*:*",),
        licenses=("Apache-2.0",),
        digests={"sha256": "ABCDEF"},
    )

    asset = assertion.asset_assertion()
    relationship = assertion.containment_assertion()
    assert asset.asset == component_identity().asset_ref
    assert asset.attributes["component"]["purl"] == "pkg:pypi/ray@2.3.1"
    assert asset.attributes["component"]["digests"] == {"sha256": "abcdef"}
    assert asset.attributes["component"]["locations"] == [
        "/usr/local/lib/python3.11/site-packages/ray"
    ]
    assert relationship.source == TARGET
    assert relationship.target == asset.asset
    assert relationship.kind is RelationshipKind.CONTAINS_COMPONENT


def test_vulnerability_identity_deduplicates_scanner_observations() -> None:
    grype = vulnerability()
    trivy = replace(
        grype,
        source_uid="trivy:CVE-2023-6020:ray",
        evidence=evidence("trivy"),
        match_method=VulnerabilityMatchMethod.ECOSYSTEM,
        match_confidence=0.95,
    )
    assert grype.canonical_key == trivy.canonical_key


def test_vulnerability_rejects_non_component_reference() -> None:
    with pytest.raises(ValueError, match="must reference a software component"):
        replace(vulnerability(), component=TARGET)


def test_component_without_purl_requires_version() -> None:
    with pytest.raises(ValueError, match="without a purl must have a version"):
        replace(component_identity(), purl=None, version=None)


def test_vulnerability_batch_requires_authoritative_complete_coverage_to_resolve() -> None:
    batch = VulnerabilityBatch(
        connector_id="denali.grype",
        connection_id="local",
        run_id="run-1",
        scope_key="workload-1",
        collected_at=OBSERVED_AT,
        coverage=(Coverage("vulnerabilities", CoverageState.PARTIAL, "workload-1"),),
        vulnerabilities=(vulnerability(),),
        authoritative=True,
    )
    assert batch.may_resolve_missing is False
    assert replace(
        batch,
        coverage=(Coverage("vulnerabilities", CoverageState.COMPLETE, "workload-1"),),
    ).may_resolve_missing is True


def test_vulnerability_batch_rejects_duplicate_source_identity() -> None:
    item = vulnerability()
    with pytest.raises(ValueError, match="cannot repeat a source_uid"):
        VulnerabilityBatch(
            connector_id="denali.grype",
            connection_id="local",
            run_id="run-1",
            scope_key="workload-1",
            collected_at=OBSERVED_AT,
            coverage=(Coverage("vulnerabilities", CoverageState.COMPLETE, "workload-1"),),
            vulnerabilities=(item, item),
        )
