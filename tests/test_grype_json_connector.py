from __future__ import annotations

from datetime import UTC, datetime

import pytest

from denali.connectors.grype_json import GrypeImportError, GrypeJsonConnector
from denali.connectors.syft_json import normalize_component_artifact
from denali.domain import (
    AssetKind,
    AssetRef,
    CoverageState,
    ExploitState,
    FindingState,
    VulnerabilityFixState,
    VulnerabilityMatchMethod,
)

COLLECTED_AT = datetime(2026, 8, 27, 13, 0, tzinfo=UTC)
TARGET = AssetRef(AssetKind.AI_WORKLOAD, "aws:123:us-east-1:workload-1")


def artifact() -> dict:
    return {
        "id": "artifact-1",
        "name": "ray",
        "version": "2.3.1",
        "type": "python",
        "foundBy": "python-installed-package-cataloger",
        "locations": [{"path": "/usr/lib/python/ray"}],
        "language": "python",
        "cpes": ["cpe:2.3:a:ray_project:ray:2.3.1:*:*:*:*:*:*:*"],
        "purl": "pkg:pypi/ray@2.3.1",
        "metadata": {"setupPy": "PASSWORD=do-not-retain"},
    }


def match(
    vulnerability_id: str = "GHSA-xxxx-yyyy-zzzz",
    match_type: str = "exact-direct-match",
) -> dict:
    return {
        "vulnerability": {
            "id": vulnerability_id,
            "dataSource": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
            "namespace": "github:language:python",
            "severity": "High",
            "description": "Ray is vulnerable to local file inclusion.",
            "cvss": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "version": "3.1",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "metrics": {"baseScore": 7.5},
                }
            ],
            "epss": [
                {
                    "cve": "CVE-2023-6020",
                    "epss": 0.81,
                    "percentile": 0.98,
                    "date": "2026-08-26",
                }
            ],
            "cwes": ["CWE-22"],
            "fix": {"state": "fixed", "versions": ["2.8.1"]},
            "risk": 72.1,
            "urls": ["https://secret.invalid/do-not-retain"],
        },
        "relatedVulnerabilities": [{"id": "CVE-2023-6020"}],
        "matchDetails": [
            {
                "type": match_type,
                "matcher": "python-matcher",
                "searchedBy": {"versionConstraint": "< 2.8.1"},
            }
        ],
        "artifact": artifact(),
    }


def report(matches: list | None = None, ignored: list | None = None) -> dict:
    return {
        "matches": [match()] if matches is None else matches,
        "ignoredMatches": [] if ignored is None else ignored,
        "source": {
            "type": "image",
            "target": "registry.example/agent",
            "manifest": {"registryToken": "do-not-retain"},
        },
        "descriptor": {
            "name": "grype",
            "version": "0.116.1",
            "timestamp": "2026-08-27T12:55:00Z",
            "db": {
                "status": {
                    "schemaVersion": "6.1.9",
                    "built": "2026-08-27T09:17:14Z",
                }
            },
        },
    }


def collect(document: object, *, authoritative: bool = False):
    return GrypeJsonConnector().collect(
        document,
        target=TARGET,
        connection_id="local-grype",
        run_id="run-1",
        scope_key="fixture-workload",
        source_locator="file:///grype.json",
        collected_at=COLLECTED_AT,
        authoritative=authoritative,
    )


def test_grype_normalizes_current_json_without_inventing_exploit_evidence() -> None:
    batch = collect(report())
    finding = batch.vulnerabilities[0]

    assert batch.coverage[0].state is CoverageState.COMPLETE
    assert finding.vulnerability_id == "CVE-2023-6020"
    assert finding.aliases == ("GHSA-XXXX-YYYY-ZZZZ",)
    assert finding.fix_state is VulnerabilityFixState.FIXED
    assert finding.fixed_versions == ("2.8.1",)
    assert finding.cvss_score == 7.5
    assert finding.match_method is VulnerabilityMatchMethod.EXACT_DIRECT
    assert finding.match_confidence == 1.0
    assert finding.exploit_state is ExploitState.UNKNOWN
    assert finding.database_version == "6.1.9"
    assert finding.database_built_at == datetime(2026, 8, 27, 9, 17, 14, tzinfo=UTC)
    assert finding.attributes["grype"]["epss"][0]["score"] == 0.81
    assert finding.attributes["grype"]["match_confidence_basis"] == (
        "denali_derived_from_match_type"
    )
    assert finding.attributes["component"] == {
        "artifact_id": "artifact-1",
        "name": "ray",
        "version": "2.3.1",
        "ecosystem": "python",
        "package_type": "python",
        "purl": "pkg:pypi/ray@2.3.1",
        "location": "/usr/lib/python/ray",
        "locations": ["/usr/lib/python/ray"],
    }
    assert batch.scan_subject is not None
    assert batch.scan_subject.artifact_kind == "container_image"
    assert batch.scan_subject.artifact_locator == "registry.example/agent"
    assert batch.scan_subject.evidence.observed_at == COLLECTED_AT
    assert "do-not-retain" not in repr(batch)


def test_grype_and_syft_derive_the_same_component_occurrence_identity() -> None:
    grype_component = collect(report()).vulnerabilities[0].component
    syft_occurrences, _ = normalize_component_artifact(
        artifact(), target=TARGET, source_type="image"
    )
    assert grype_component == syft_occurrences[0].identity.asset_ref


def test_grype_emits_one_observation_for_package_with_many_evidence_paths() -> None:
    item = match()
    item["artifact"]["locations"] = [
        {"path": "/var/lib/dpkg/status"},
        {"path": "/var/lib/dpkg/info/ray.list"},
        {"path": "/var/lib/dpkg/info/ray.md5sums"},
    ]

    batch = collect(report(matches=[item]))

    assert len(batch.vulnerabilities) == 1
    assert batch.vulnerabilities[0].attributes["component"]["locations"] == [
        "/var/lib/dpkg/status",
        "/var/lib/dpkg/info/ray.list",
        "/var/lib/dpkg/info/ray.md5sums",
    ]


def test_grype_retains_ignored_match_as_suppressed_with_cpe_confidence() -> None:
    ignored = match("CVE-2024-9999", "cpe-match")
    ignored["relatedVulnerabilities"] = []
    ignored["appliedIgnoreRules"] = [
        {"vulnerability": "CVE-2024-9999", "package": {"name": "ray"}}
    ]
    batch = collect(report(matches=[], ignored=[ignored]))
    finding = batch.vulnerabilities[0]
    assert finding.state is FindingState.SUPPRESSED
    assert finding.match_method is VulnerabilityMatchMethod.CPE
    assert finding.match_confidence == 0.6
    assert finding.attributes["grype"]["applied_ignore_rules"][0]["package_name"] == "ray"


def test_grype_coverage_is_explicit_for_empty_and_malformed_reports() -> None:
    empty = collect(report(matches=[], ignored=[]), authoritative=True)
    assert empty.coverage[0].state is CoverageState.COMPLETE
    assert empty.may_resolve_missing is True
    assert empty.scan_subject is not None
    assert empty.scan_subject.artifact_locator == "registry.example/agent"

    partial = collect(report(matches=[match(), "bad-entry"], ignored=[]))
    assert partial.coverage[0].state is CoverageState.PARTIAL
    assert len(partial.vulnerabilities) == 1

    failed = collect(report(matches=["bad-entry"], ignored=[]))
    assert failed.coverage[0].state is CoverageState.FAILED


def test_grype_requires_native_report_shape() -> None:
    with pytest.raises(GrypeImportError, match="descriptor"):
        collect({"matches": [], "descriptor": {"name": "other"}})
    with pytest.raises(GrypeImportError, match="matches"):
        collect({"descriptor": {"name": "grype"}})


def test_grype_normalizes_structured_image_subject_without_retaining_source_metadata() -> None:
    document = report(matches=[], ignored=[])
    document["source"] = {
        "type": "image",
        "target": {
            "userInput": "docker:registry.example/agent:2026-08-27",
            "imageID": "sha256:image-id",
            "manifestDigest": "sha256:manifest-digest",
            "tags": ["do-not-retain"],
        },
        "manifest": {"registryToken": "do-not-retain"},
    }

    batch = collect(document)

    assert batch.scan_subject is not None
    assert batch.scan_subject.artifact_kind == "container_image"
    assert batch.scan_subject.artifact_locator == "registry.example/agent:2026-08-27"
    assert batch.scan_subject.artifact_digest == "sha256:manifest-digest"
    assert "do-not-retain" not in repr(batch.scan_subject)
