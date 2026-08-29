from __future__ import annotations

from datetime import UTC, datetime

import pytest

from denali.connectors.syft_json import SyftImportError, SyftJsonConnector
from denali.domain import AssetKind, AssetRef, CoverageState, RelationshipKind

OBSERVED_AT = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
TARGET = AssetRef(AssetKind.AI_WORKLOAD, "aws:123:us-east-1:workload-1")


def artifact(
    artifact_id: str = "artifact-1", location: str = "/usr/lib/python/ray"
) -> dict:
    return {
        "id": artifact_id,
        "name": "ray",
        "version": "2.3.1",
        "type": "python",
        "foundBy": "python-installed-package-cataloger",
        "locations": [{"path": location}],
        "licenses": [{"value": "Apache-2.0", "spdxExpression": "Apache-2.0"}],
        "language": "python",
        "cpes": ["cpe:2.3:a:ray_project:ray:2.3.1:*:*:*:*:*:*:*"],
        "purl": "pkg:pypi/ray@2.3.1",
        "metadata": {"installScript": "TOKEN=do-not-retain"},
    }


def report(artifacts: list | None = None) -> dict:
    return {
        "artifacts": [artifact()] if artifacts is None else artifacts,
        "artifactRelationships": [],
        "source": {
            "id": "sha256:image",
            "name": "registry.example/agent",
            "version": "sha256:image",
            "type": "image",
            "metadata": {"manifest": {"password": "do-not-retain"}},
        },
        "distro": {"id": "ubuntu", "versionID": "24.04"},
        "descriptor": {"name": "syft", "version": "1.42.3"},
        "schema": {"version": "16.1.3"},
    }


def collect(document: object):
    return SyftJsonConnector().collect(
        document,
        target=TARGET,
        target_name="agent workload",
        connection_id="local-syft",
        run_id="run-1",
        scope_key="fixture-workload",
        source_locator="file:///sbom.json",
        collected_at=OBSERVED_AT,
    )


def test_syft_imports_one_package_occurrence_and_retains_all_locations() -> None:
    document = report(
        [
            artifact(),
            artifact("artifact-duplicate"),
            artifact("artifact-2", "/opt/venv/ray"),
        ]
    )
    batch = collect(document)

    assert batch.coverage[0].state is CoverageState.COMPLETE
    assert len(batch.assets) == 2  # explicit target plus one package occurrence
    assert len(batch.relationships) == 1
    assert {item.kind for item in batch.relationships} == {
        RelationshipKind.CONTAINS_COMPONENT
    }
    components = [item for item in batch.assets if item.asset.kind is AssetKind.SOFTWARE_COMPONENT]
    assert components[0].attributes["component"]["locations"] == [
        "/usr/lib/python/ray",
        "/opt/venv/ray",
    ]
    assert {item.attributes["component"]["scope"] for item in components} == {"installed"}
    assert components[0].attributes["syft"]["artifact_ids"] == (
        "artifact-1",
        "artifact-duplicate",
        "artifact-2",
    )
    assert "do-not-retain" not in repr(batch)


def test_syft_malformed_siblings_make_coverage_partial_or_failed() -> None:
    partial = collect(report([artifact(), "bad-entry"]))
    assert partial.coverage[0].state is CoverageState.PARTIAL
    assert len(partial.assets) == 2

    failed = collect(report(["bad-entry"]))
    assert failed.coverage[0].state is CoverageState.FAILED
    assert len(failed.assets) == 1  # target evidence remains useful


def test_syft_empty_valid_report_is_complete() -> None:
    batch = collect(report([]))
    assert batch.coverage[0].state is CoverageState.COMPLETE
    assert len(batch.assets) == 1
    assert batch.relationships == ()


def test_syft_requires_native_report_shape() -> None:
    with pytest.raises(SyftImportError, match="descriptor"):
        collect({"artifacts": [], "descriptor": {"name": "other"}})
    with pytest.raises(SyftImportError, match="artifacts"):
        collect({"descriptor": {"name": "syft"}})
