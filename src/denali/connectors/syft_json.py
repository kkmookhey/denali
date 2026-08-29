"""Import Syft JSON as evidence-bearing software-component inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from denali.connectors.json_file import JsonImportError, load_json_file
from denali.domain import (
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    ComponentIdentity,
    ComponentScope,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    Evidence,
    InventoryBatch,
    SoftwareComponentAssertion,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.syft"
CAPABILITIES = ConnectorCapabilities(inventory=True, relationships=True)
COMPONENT_PLANE = "software_components"
MAX_ARTIFACTS = 500_000
MAX_LOCATIONS_PER_ARTIFACT = 1_000
MAX_IDENTIFIERS_PER_ARTIFACT = 200


class SyftImportError(ValueError):
    """A bounded normalization error that never includes arbitrary source content."""


@dataclass(frozen=True, slots=True)
class ComponentOccurrence:
    identity: ComponentIdentity
    locations: tuple[str, ...]
    scope: ComponentScope
    cpes: tuple[str, ...]
    licenses: tuple[str, ...]
    digests: dict[str, str]
    artifact_id: str
    found_by: str | None


class SyftJsonConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def collect(
        self,
        document: Any,
        *,
        target: AssetRef,
        target_name: str,
        connection_id: str,
        run_id: str,
        scope_key: str,
        source_locator: str,
        collected_at: datetime | None = None,
        force_partial: bool = False,
    ) -> InventoryBatch:
        observed_at = collected_at or datetime.now(UTC)
        if not isinstance(document, dict):
            raise SyftImportError("Syft report root must be a JSON object")
        artifacts = document.get("artifacts")
        if not isinstance(artifacts, list):
            raise SyftImportError("Syft report artifacts must be an array")
        if len(artifacts) > MAX_ARTIFACTS:
            raise SyftImportError(
                f"Syft report exceeds the {MAX_ARTIFACTS} artifact safety limit"
            )
        descriptor = _object(document.get("descriptor"))
        if (_text(descriptor.get("name")) or "").casefold() != "syft":
            raise SyftImportError("report descriptor does not identify Syft")
        source = _object(document.get("source"))
        schema = _object(document.get("schema"))
        distro = _object(document.get("distro"))
        source_type = _text(source.get("type")) or "unknown"
        descriptor_version = _text(descriptor.get("version"))
        schema_version = _text(schema.get("version"))
        source_id = _text(source.get("id"))

        target_evidence = Evidence(
            source_type="syft_json",
            locator=f"{source_locator}#source",
            observed_at=observed_at,
            payload={
                "tool": "syft",
                "tool_version": descriptor_version,
                "schema_version": schema_version,
                "source_id": source_id,
                "source_type": source_type,
                "source_name": _text(source.get("name"), 1_000),
                "source_version": _text(source.get("version"), 512),
                "distro_id": _text(distro.get("id"), 256),
                "distro_version": _text(distro.get("versionID"), 256),
            },
        )
        target_assertion = AssetAssertion(
            asset=target,
            coverage_plane=COMPONENT_PLANE,
            display_name=_required_text(target_name, "target_name", 1_000),
            assertion_type=AssertionType.OBSERVED,
            confidence=1.0,
            evidence=target_evidence,
            attributes={
                "software_inventory": {
                    "source": "syft",
                    "tool_version": descriptor_version,
                    "schema_version": schema_version,
                    "source_type": source_type,
                    "source_id": source_id,
                    "distro": {
                        "id": _text(distro.get("id"), 256),
                        "version": _text(distro.get("versionID"), 256),
                    },
                }
            },
        )

        components: dict[AssetRef, SoftwareComponentAssertion] = {}
        warnings: list[str] = []
        for position, artifact in enumerate(artifacts):
            try:
                occurrences, item_warnings = normalize_component_artifact(
                    artifact,
                    target=target,
                    source_type=source_type,
                )
            except SyftImportError as error:
                warnings.append(f"artifact {position}: {error}")
                continue
            warnings.extend(f"artifact {position}: {warning}" for warning in item_warnings)
            for occurrence_index, occurrence in enumerate(occurrences):
                evidence = Evidence(
                    source_type="syft_json",
                    locator=(
                        f"{source_locator}#artifact={position}&occurrence={occurrence_index}"
                    ),
                    observed_at=observed_at,
                    payload={
                        "artifact_id": occurrence.artifact_id,
                        "found_by": occurrence.found_by,
                        "location": occurrence.identity.location,
                        "locations": list(occurrence.locations),
                        "tool_version": descriptor_version,
                        "schema_version": schema_version,
                        "source_id": source_id,
                    },
                )
                assertion = SoftwareComponentAssertion(
                    identity=occurrence.identity,
                    coverage_plane=COMPONENT_PLANE,
                    scope=occurrence.scope,
                    assertion_type=AssertionType.OBSERVED,
                    confidence=1.0,
                    evidence=evidence,
                    locations=occurrence.locations,
                    cpes=occurrence.cpes,
                    licenses=occurrence.licenses,
                    digests=occurrence.digests,
                    attributes={
                        "syft": {
                            "artifact_ids": [occurrence.artifact_id],
                            "locations": list(occurrence.locations),
                            "found_by": (
                                [occurrence.found_by] if occurrence.found_by else []
                            ),
                            "tool_version": descriptor_version,
                            "schema_version": schema_version,
                        }
                    },
                )
                previous = components.get(occurrence.identity.asset_ref)
                components[occurrence.identity.asset_ref] = (
                    assertion if previous is None else _merge_component(previous, assertion)
                )

        if artifacts and not components:
            state = CoverageState.FAILED
        elif warnings or force_partial:
            state = CoverageState.PARTIAL
        else:
            state = CoverageState.COMPLETE
        if force_partial:
            warnings.append("caller marked the report partial")
        detail = "; ".join(dict.fromkeys(warnings))[:4_000] if warnings else None
        component_values = tuple(components.values())
        return InventoryBatch(
            connector_id=CONNECTOR_ID,
            connection_id=connection_id,
            run_id=run_id,
            scope_key=scope_key,
            collected_at=observed_at,
            coverage=(Coverage(COMPONENT_PLANE, state, scope_key, detail),),
            assets=(target_assertion, *(item.asset_assertion() for item in component_values)),
            relationships=tuple(item.containment_assertion() for item in component_values),
        )


def normalize_component_artifact(
    artifact: Any,
    *,
    target: AssetRef,
    source_type: str,
) -> tuple[tuple[ComponentOccurrence, ...], tuple[str, ...]]:
    if not isinstance(artifact, dict):
        raise SyftImportError("entry was not an object")
    artifact_id = _required_text(artifact.get("id"), "id", 1_000)
    name = _required_text(artifact.get("name"), "name", 2_000)
    version = _text(artifact.get("version"), 2_000)
    package_type = _required_text(artifact.get("type"), "type", 256)
    purl = _text(artifact.get("purl"), 4_096)
    if purl and not purl.startswith("pkg:"):
        raise SyftImportError("purl did not start with 'pkg:'")
    if not purl and not version:
        raise SyftImportError("component had neither purl nor version")
    language = _text(artifact.get("language"), 256)
    ecosystem = language or package_type
    found_by = _text(artifact.get("foundBy"), 512)
    warnings: list[str] = []
    locations = _locations(artifact.get("locations"), warnings)
    cpes = _identifiers(artifact.get("cpes"), "cpe", warnings)
    licenses = _licenses(artifact.get("licenses"), warnings)
    digests = _digests(artifact.get("digests"), warnings)
    scope = _component_scope(source_type, found_by, package_type)
    retained_locations = tuple(location for location in locations if location is not None)
    occurrences = (
        ComponentOccurrence(
            identity=ComponentIdentity(
                target=target,
                name=name,
                version=version,
                ecosystem=ecosystem,
                package_type=package_type,
                purl=purl,
                location=retained_locations[0] if retained_locations else None,
            ),
            locations=retained_locations,
            scope=scope,
            cpes=cpes,
            licenses=licenses,
            digests=digests,
            artifact_id=artifact_id,
            found_by=found_by,
        ),
    )
    return occurrences, tuple(warnings)


def import_main() -> None:
    parser = argparse.ArgumentParser(description="Import a Syft JSON SBOM into Denali")
    parser.add_argument("path", type=Path, help="Syft native JSON report")
    parser.add_argument(
        "--target-kind",
        required=True,
        choices=[kind.value for kind in AssetKind if kind is not AssetKind.SOFTWARE_COMPONENT],
    )
    parser.add_argument("--target-key", required=True, help="existing or explicit target key")
    parser.add_argument("--target-name", help="display name; defaults to target key")
    parser.add_argument("--connection-id", help="stable scanner connection id")
    parser.add_argument("--scope-key", help="explicit reconciliation scope")
    parser.add_argument(
        "--partial",
        action="store_true",
        help="prevent absence from withdrawing prior component inventory",
    )
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"),
    )
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    args = parser.parse_args()
    if not args.dsn:
        raise SystemExit("--dsn or DENALI_DSN is required")

    try:
        document, digest, locator = load_json_file(args.path)
        target = AssetRef(AssetKind(args.target_kind), args.target_key)
        scope_key = args.scope_key or target.canonical_key
        connection_id = args.connection_id or f"syft:{target.canonical_key}"
        batch = SyftJsonConnector().collect(
            document,
            target=target,
            target_name=args.target_name or args.target_key,
            connection_id=connection_id,
            run_id=(
                f"syft-{digest[:20]}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%f')}"
            ),
            scope_key=scope_key,
            source_locator=locator,
            force_partial=args.partial,
        )
    except (JsonImportError, SyftImportError, ValueError) as error:
        raise SystemExit(str(error)) from error

    migrate(args.dsn)
    result = PostgresInventoryRepository(args.dsn).ingest(args.tenant_id, batch)
    state = batch.coverage[0].state.value
    print(
        f"Imported {result['assets'] - 1} Syft component occurrences and "
        f"{result['relationships']} containment relationships; coverage={state}"
    )
    if state in {CoverageState.PARTIAL.value, CoverageState.FAILED.value}:
        raise SystemExit(2)


def _merge_component(
    previous: SoftwareComponentAssertion,
    current: SoftwareComponentAssertion,
) -> SoftwareComponentAssertion:
    previous_syft = dict(previous.attributes.get("syft", {}))
    current_syft = dict(current.attributes.get("syft", {}))
    artifact_ids = tuple(
        dict.fromkeys(
            [*previous_syft.get("artifact_ids", []), *current_syft.get("artifact_ids", [])]
        )
    )
    found_by = tuple(
        dict.fromkeys(
            [*previous_syft.get("found_by", []), *current_syft.get("found_by", [])]
        )
    )
    return replace(
        previous,
        locations=tuple(dict.fromkeys((*previous.locations, *current.locations))),
        cpes=tuple(dict.fromkeys((*previous.cpes, *current.cpes))),
        licenses=tuple(dict.fromkeys((*previous.licenses, *current.licenses))),
        digests={**dict(previous.digests), **dict(current.digests)},
        attributes={
            **dict(previous.attributes),
            "syft": {
                **previous_syft,
                "artifact_ids": artifact_ids,
                "found_by": found_by,
                "locations": tuple(
                    dict.fromkeys(
                        [
                            *previous_syft.get("locations", []),
                            *current_syft.get("locations", []),
                        ]
                    )
                ),
            },
        },
    )


def _locations(value: Any, warnings: list[str]) -> tuple[str | None, ...]:
    if value is None:
        return (None,)
    if not isinstance(value, list):
        warnings.append("locations was not an array")
        return (None,)
    if len(value) > MAX_LOCATIONS_PER_ARTIFACT:
        warnings.append(
            f"locations exceeded the {MAX_LOCATIONS_PER_ARTIFACT} item normalization limit"
        )
    output: list[str] = []
    for item in value[:MAX_LOCATIONS_PER_ARTIFACT]:
        if not isinstance(item, dict):
            continue
        path = _text(item.get("path"), 4_096) or _text(item.get("accessPath"), 4_096)
        if path:
            output.append(path)
    return tuple(dict.fromkeys(output)) or (None,)


def _identifiers(value: Any, field: str, warnings: list[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        warnings.append(f"{field}s was not an array")
        return ()
    if len(value) > MAX_IDENTIFIERS_PER_ARTIFACT:
        warnings.append(
            f"{field}s exceeded the {MAX_IDENTIFIERS_PER_ARTIFACT} item limit"
        )
    output: list[str] = []
    for item in value[:MAX_IDENTIFIERS_PER_ARTIFACT]:
        candidate = item.get(field) if isinstance(item, dict) else item
        text = _text(candidate, 4_096)
        if text:
            output.append(text)
    return tuple(dict.fromkeys(output))


def _licenses(value: Any, warnings: list[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        warnings.append("licenses was not an array")
        return ()
    if len(value) > MAX_IDENTIFIERS_PER_ARTIFACT:
        warnings.append(
            f"licenses exceeded the {MAX_IDENTIFIERS_PER_ARTIFACT} item limit"
        )
    output: list[str] = []
    for item in value[:MAX_IDENTIFIERS_PER_ARTIFACT]:
        if isinstance(item, dict):
            candidate = item.get("spdxExpression") or item.get("value")
        else:
            candidate = item
        text = _text(candidate, 1_000)
        if text:
            output.append(text)
    return tuple(dict.fromkeys(output))


def _digests(value: Any, warnings: list[str]) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, list):
        warnings.append("digests was not an array")
        return {}
    output: dict[str, str] = {}
    for item in value[:MAX_IDENTIFIERS_PER_ARTIFACT]:
        if not isinstance(item, dict):
            continue
        algorithm = _text(item.get("algorithm"), 128)
        digest = _text(item.get("value"), 4_096)
        if algorithm and digest:
            output[algorithm] = digest
    return output


def _component_scope(
    source_type: str, found_by: str | None, package_type: str
) -> ComponentScope:
    marker = (found_by or "").casefold()
    if any(value in marker for value in ("installed", "-db-")):
        return ComponentScope.INSTALLED
    if any(value in marker for value in ("archive", "binary", "gguf")):
        return ComponentScope.EMBEDDED
    if source_type.casefold() in {"image", "container", "rootfs"}:
        return ComponentScope.INSTALLED
    if package_type.casefold() in {"apk", "deb", "rpm", "alpm"}:
        return ComponentScope.INSTALLED
    if source_type.casefold() in {"directory", "file"}:
        return ComponentScope.DECLARED
    return ComponentScope.UNKNOWN


def _required_text(value: Any, field: str, limit: int) -> str:
    text = _text(value)
    if not text:
        raise SyftImportError(f"missing {field}")
    if len(text) > limit:
        raise SyftImportError(f"{field} exceeded the identity limit")
    return text


def _text(value: Any, limit: int | None = None) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    output = value.strip()
    return output[:limit] if limit is not None else output


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def document_fingerprint(document: Any) -> str:
    """Stable helper for in-memory callers that do not load a report from a file."""

    normalized = json.dumps(document, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(normalized.encode()).hexdigest()


if __name__ == "__main__":
    import_main()
