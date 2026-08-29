"""Import Grype JSON as scanner-neutral vulnerability observations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from denali.connectors.json_file import JsonImportError, load_json_file
from denali.connectors.syft_json import SyftImportError, normalize_component_artifact
from denali.domain import (
    AssetKind,
    AssetRef,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    Evidence,
    ExploitState,
    FindingSeverity,
    FindingState,
    VulnerabilityAssertion,
    VulnerabilityBatch,
    VulnerabilityFixState,
    VulnerabilityMatchMethod,
    VulnerabilityScanSubject,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.grype"
CAPABILITIES = ConnectorCapabilities(findings=True)
VULNERABILITY_PLANE = "vulnerabilities"
MAX_MATCHES = 500_000
MAX_ALIASES = 200
MAX_FIXED_VERSIONS = 200
MAX_MATCH_DETAILS = 50
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class GrypeImportError(ValueError):
    """A bounded normalization error that never includes arbitrary source content."""


class GrypeJsonConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def collect(
        self,
        document: Any,
        *,
        target: AssetRef,
        connection_id: str,
        run_id: str,
        scope_key: str,
        source_locator: str,
        collected_at: datetime | None = None,
        authoritative: bool = False,
        force_partial: bool = False,
    ) -> VulnerabilityBatch:
        fallback_time = collected_at or datetime.now(UTC)
        if not isinstance(document, dict):
            raise GrypeImportError("Grype report root must be a JSON object")
        matches = document.get("matches")
        ignored = document.get("ignoredMatches", [])
        if not isinstance(matches, list):
            raise GrypeImportError("Grype report matches must be an array")
        if not isinstance(ignored, list):
            raise GrypeImportError("Grype report ignoredMatches must be an array")
        if len(matches) + len(ignored) > MAX_MATCHES:
            raise GrypeImportError(
                f"Grype report exceeds the {MAX_MATCHES} match safety limit"
            )
        descriptor = _object(document.get("descriptor"))
        if (_text(descriptor.get("name")) or "").casefold() != "grype":
            raise GrypeImportError("report descriptor does not identify Grype")

        source = _object(document.get("source"))
        source_type = _text(source.get("type")) or "unknown"
        tool_version = _text(descriptor.get("version"), 256)
        observed_at = _parse_time(descriptor.get("timestamp")) or fallback_time
        scan_subject = _scan_subject(
            source,
            target=target,
            observed_at=fallback_time,
            source_locator=source_locator,
            tool_version=tool_version,
        )
        database = _database_metadata(descriptor)
        warnings: list[str] = []
        observations: dict[str, VulnerabilityAssertion] = {}

        for state, values, group in (
            (FindingState.OPEN, matches, "match"),
            (FindingState.SUPPRESSED, ignored, "ignored match"),
        ):
            for position, match in enumerate(values):
                try:
                    normalized, item_warnings = _normalize_match(
                        match,
                        state=state,
                        target=target,
                        source_type=source_type,
                        source_locator=source_locator,
                        position=position,
                        observed_at=observed_at,
                        tool_version=tool_version,
                        database=database,
                    )
                except (GrypeImportError, SyftImportError, ValueError) as error:
                    warnings.append(f"{group} {position}: {error}")
                    continue
                warnings.extend(f"{group} {position}: {warning}" for warning in item_warnings)
                for observation in normalized:
                    if observation.source_uid in observations:
                        warnings.append(
                            f"{group} {position}: duplicate scanner observation was ignored"
                        )
                        continue
                    observations[observation.source_uid] = observation

        source_count = len(matches) + len(ignored)
        if source_count and not observations:
            coverage_state = CoverageState.FAILED
        elif warnings or force_partial:
            coverage_state = CoverageState.PARTIAL
        else:
            coverage_state = CoverageState.COMPLETE
        if force_partial:
            warnings.append("caller marked the report partial")
        detail = "; ".join(dict.fromkeys(warnings))[:4_000] if warnings else None
        return VulnerabilityBatch(
            connector_id=CONNECTOR_ID,
            connection_id=connection_id,
            run_id=run_id,
            scope_key=scope_key,
            collected_at=fallback_time,
            coverage=(Coverage(VULNERABILITY_PLANE, coverage_state, scope_key, detail),),
            vulnerabilities=tuple(observations.values()),
            scan_subject=scan_subject,
            authoritative=authoritative,
        )


def import_main() -> None:
    parser = argparse.ArgumentParser(description="Import a Grype JSON report into Denali")
    parser.add_argument("path", type=Path, help="Grype native JSON report")
    parser.add_argument(
        "--target-kind",
        required=True,
        choices=[kind.value for kind in AssetKind if kind is not AssetKind.SOFTWARE_COMPONENT],
    )
    parser.add_argument("--target-key", required=True, help="existing or explicit target key")
    parser.add_argument("--connection-id", help="stable scanner connection id")
    parser.add_argument("--scope-key", help="explicit reconciliation scope")
    parser.add_argument(
        "--authoritative",
        action="store_true",
        help="allow a complete unfiltered report to resolve missing prior observations",
    )
    parser.add_argument(
        "--partial",
        action="store_true",
        help="mark the report incomplete and prevent resolution by absence",
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
        connection_id = args.connection_id or f"grype:{target.canonical_key}"
        batch = GrypeJsonConnector().collect(
            document,
            target=target,
            connection_id=connection_id,
            run_id=(
                f"grype-{digest[:20]}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%f')}"
            ),
            scope_key=scope_key,
            source_locator=locator,
            authoritative=args.authoritative,
            force_partial=args.partial,
        )
    except (JsonImportError, GrypeImportError, ValueError) as error:
        raise SystemExit(str(error)) from error

    migrate(args.dsn)
    result = PostgresInventoryRepository(args.dsn).ingest_vulnerabilities(
        args.tenant_id, batch
    )
    state = batch.coverage[0].state.value
    print(
        f"Imported {result['observations']} Grype observations across "
        f"{result['vulnerabilities']} vulnerabilities; coverage={state}"
    )
    if state in {CoverageState.PARTIAL.value, CoverageState.FAILED.value}:
        raise SystemExit(2)


def _normalize_match(
    match: Any,
    *,
    state: FindingState,
    target: AssetRef,
    source_type: str,
    source_locator: str,
    position: int,
    observed_at: datetime,
    tool_version: str | None,
    database: dict[str, Any],
) -> tuple[tuple[VulnerabilityAssertion, ...], tuple[str, ...]]:
    if not isinstance(match, dict):
        raise GrypeImportError("entry was not an object")
    vulnerability = _object(match.get("vulnerability"))
    raw_id = _required_text(vulnerability.get("id"), "vulnerability id", 256).upper()
    related = match.get("relatedVulnerabilities", [])
    related_ids = _related_ids(related)
    canonical_id = next((item for item in related_ids if _CVE_PATTERN.match(item)), raw_id)
    aliases = tuple(
        dict.fromkeys(item for item in (raw_id, *related_ids) if item != canonical_id)
    )[:MAX_ALIASES]
    artifact = match.get("artifact")
    occurrences, component_warnings = normalize_component_artifact(
        artifact,
        target=target,
        source_type=source_type,
    )
    method, confidence, match_details = _match_method(match.get("matchDetails"))
    severity = _severity(vulnerability.get("severity"))
    fix = _object(vulnerability.get("fix"))
    fixed_versions = _string_list(fix.get("versions"), MAX_FIXED_VERSIONS, 2_000)
    cvss_score, cvss_vector = _cvss(vulnerability.get("cvss"))
    source_namespace = _text(vulnerability.get("namespace"), 1_000)
    data_source = _text(vulnerability.get("dataSource"), 4_096)
    cwes = _string_list(vulnerability.get("cwes"), MAX_ALIASES, 256)
    epss = _epss(vulnerability.get("epss"))
    applied_rules = _ignore_rules(match.get("appliedIgnoreRules"))
    output: list[VulnerabilityAssertion] = []
    for occurrence_index, occurrence in enumerate(occurrences):
        source_uid = _source_uid(
            raw_id,
            source_namespace,
            occurrence.identity.asset_ref.canonical_key,
            target.canonical_key,
        )
        group_name = "ignoredMatch" if state is FindingState.SUPPRESSED else "match"
        evidence = Evidence(
            source_type="grype_json",
            locator=(
                f"{source_locator}#{group_name}={position}&occurrence={occurrence_index}"
            ),
            observed_at=observed_at,
            payload={
                "vulnerability_id": raw_id,
                "namespace": source_namespace,
                "artifact_id": occurrence.artifact_id,
                "location": occurrence.identity.location,
                "locations": list(occurrence.locations),
                "match_types": [item["type"] for item in match_details],
                "tool_version": tool_version,
                "database_schema_version": database.get("schema_version"),
                "suppressed": state is FindingState.SUPPRESSED,
            },
        )
        output.append(
            VulnerabilityAssertion(
                source_uid=source_uid,
                vulnerability_id=canonical_id,
                aliases=aliases,
                component=occurrence.identity.asset_ref,
                target=target,
                title=canonical_id,
                description=_text(vulnerability.get("description"), 8_000),
                severity=severity,
                state=state,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                fix_state=_fix_state(fix.get("state")),
                fixed_versions=fixed_versions,
                exploit_state=ExploitState.UNKNOWN,
                observed_at=observed_at,
                evidence=evidence,
                match_method=method,
                match_confidence=confidence,
                database_version=database.get("schema_version"),
                database_built_at=database.get("built_at"),
                attributes={
                    "component": {
                        "artifact_id": occurrence.artifact_id,
                        "name": occurrence.identity.name,
                        "version": occurrence.identity.version,
                        "ecosystem": occurrence.identity.ecosystem,
                        "package_type": occurrence.identity.package_type,
                        "purl": occurrence.identity.purl,
                        "location": occurrence.identity.location,
                        "locations": list(occurrence.locations),
                    },
                    "grype": {
                        "raw_vulnerability_id": raw_id,
                        "namespace": source_namespace,
                        "data_source": data_source,
                        "risk": _number(vulnerability.get("risk"), 0.0, 100.0),
                        "cwes": list(cwes),
                        "epss": epss,
                        "match_details": match_details,
                        "match_confidence_basis": "denali_derived_from_match_type",
                        "tool_version": tool_version,
                        "database": {
                            "schema_version": database.get("schema_version"),
                            "built_at": (
                                database["built_at"].isoformat()
                                if database.get("built_at")
                                else None
                            ),
                        },
                        "applied_ignore_rules": applied_rules,
                    }
                },
            )
        )
    return tuple(output), component_warnings


def _scan_subject(
    source: dict[str, Any],
    *,
    target: AssetRef,
    observed_at: datetime,
    source_locator: str,
    tool_version: str | None,
) -> VulnerabilityScanSubject | None:
    """Retain only the bounded artifact identity Grype says it scanned."""

    reported_type = (_text(source.get("type"), 256) or "unknown").casefold()
    raw_target = source.get("target")
    locator: str | None = None
    digest: str | None = None
    if isinstance(raw_target, str):
        locator = _text(raw_target, 4_096)
    elif isinstance(raw_target, dict):
        locator = _text(raw_target.get("userInput"), 4_096) or _text(
            raw_target.get("imageID"), 4_096
        )
        digest = _text(raw_target.get("manifestDigest"), 512)

    if locator is None:
        return None
    artifact_kind = {
        "image": "container_image",
        "container": "container_image",
        "docker": "container_image",
        "directory": "directory",
        "dir": "directory",
        "file": "file",
        "sbom": "sbom",
    }.get(reported_type, reported_type)
    if artifact_kind == "container_image":
        for prefix in ("docker:", "registry:"):
            if locator.startswith(prefix):
                locator = locator[len(prefix) :]
                break

    evidence_payload = {
        "scanner": "grype",
        "tool_version": tool_version,
        "reported_source_type": reported_type,
        "artifact_kind": artifact_kind,
        "artifact_locator": locator,
        "artifact_digest": digest,
    }
    return VulnerabilityScanSubject(
        target=target,
        artifact_kind=artifact_kind,
        artifact_locator=locator,
        artifact_digest=digest,
        evidence=Evidence(
            source_type="grype_scan_subject",
            locator=f"{source_locator}#source",
            observed_at=observed_at,
            payload=evidence_payload,
        ),
    )


def _database_metadata(descriptor: dict[str, Any]) -> dict[str, Any]:
    status = _object(_object(descriptor.get("db")).get("status"))
    return {
        "schema_version": _text(status.get("schemaVersion"), 256),
        "built_at": _parse_time(status.get("built")),
    }


def _match_method(value: Any) -> tuple[VulnerabilityMatchMethod, float, list[dict[str, Any]]]:
    if not isinstance(value, list):
        return VulnerabilityMatchMethod.UNKNOWN, 0.5, []
    details: list[dict[str, Any]] = []
    types: set[str] = set()
    for item in value[:MAX_MATCH_DETAILS]:
        if not isinstance(item, dict):
            continue
        match_type = (_text(item.get("type"), 256) or "unknown").casefold()
        types.add(match_type)
        searched_by = _object(item.get("searchedBy"))
        details.append(
            {
                "type": match_type,
                "matcher": _text(item.get("matcher"), 256),
                "version_constraint": _text(searched_by.get("versionConstraint"), 1_000),
            }
        )
    if "exact-direct-match" in types:
        return VulnerabilityMatchMethod.EXACT_DIRECT, 1.0, details
    if "exact-indirect-match" in types:
        return VulnerabilityMatchMethod.EXACT_INDIRECT, 0.95, details
    if "cpe-match" in types:
        return VulnerabilityMatchMethod.CPE, 0.6, details
    return VulnerabilityMatchMethod.UNKNOWN, 0.5, details


def _related_ids(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    output: list[str] = []
    for item in value[:MAX_ALIASES]:
        candidate = item.get("id") if isinstance(item, dict) else item
        text = _text(candidate, 256)
        if text:
            output.append(text.upper())
    return tuple(dict.fromkeys(output))


def _severity(value: Any) -> FindingSeverity:
    normalized = (_text(value) or "unknown").casefold()
    aliases = {"negligible": "informational", "info": "informational"}
    try:
        return FindingSeverity(aliases.get(normalized, normalized))
    except ValueError:
        return FindingSeverity.UNKNOWN


def _fix_state(value: Any) -> VulnerabilityFixState:
    normalized = (_text(value) or "unknown").casefold().replace("-", "_")
    aliases = {"wontfix": "wont_fix", "notfixed": "not_fixed"}
    try:
        return VulnerabilityFixState(aliases.get(normalized, normalized))
    except ValueError:
        return VulnerabilityFixState.UNKNOWN


def _cvss(value: Any) -> tuple[float | None, str | None]:
    if not isinstance(value, list):
        return None, None
    candidates: list[tuple[float, str | None]] = []
    for item in value[:MAX_ALIASES]:
        if not isinstance(item, dict):
            continue
        metrics = _object(item.get("metrics"))
        score = _number(metrics.get("baseScore"), 0.0, 10.0)
        if score is not None:
            candidates.append((score, _text(item.get("vector"), 1_000)))
    return max(candidates, key=lambda item: item[0]) if candidates else (None, None)


def _epss(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    output: list[dict[str, Any]] = []
    for item in value[:MAX_ALIASES]:
        if not isinstance(item, dict):
            continue
        output.append(
            {
                "cve": _text(item.get("cve"), 256),
                "score": _number(item.get("epss"), 0.0, 1.0),
                "percentile": _number(item.get("percentile"), 0.0, 1.0),
                "date": _text(item.get("date"), 64),
            }
        )
    return output


def _ignore_rules(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    output: list[dict[str, Any]] = []
    for item in value[:MAX_MATCH_DETAILS]:
        if not isinstance(item, dict):
            continue
        output.append(
            {
                "vulnerability": _text(item.get("vulnerability"), 256),
                "fix_state": _text(item.get("fix-state"), 128),
                "package_name": _text(item.get("package", {}).get("name"), 1_000)
                if isinstance(item.get("package"), dict)
                else None,
            }
        )
    return output


def _string_list(value: Any, count_limit: int, text_limit: int) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(
        dict.fromkeys(
            text
            for item in value[:count_limit]
            if (text := _text(item, text_limit)) is not None
        )
    )


def _source_uid(
    raw_id: str,
    namespace: str | None,
    component_key: str,
    target_key: str,
) -> str:
    material = json.dumps(
        {
            "id": raw_id,
            "namespace": namespace,
            "component": component_key,
            "target": target_key,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "grype:" + hashlib.sha256(material.encode()).hexdigest()


def _parse_time(value: Any) -> datetime | None:
    text = _text(value)
    if text is None:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _number(value: Any, minimum: float, maximum: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if minimum <= result <= maximum else None


def _required_text(value: Any, field: str, limit: int) -> str:
    text = _text(value)
    if not text:
        raise GrypeImportError(f"missing {field}")
    if len(text) > limit:
        raise GrypeImportError(f"{field} exceeded the identity limit")
    return text


def _text(value: Any, limit: int | None = None) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    output = value.strip()
    return output[:limit] if limit is not None else output


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


if __name__ == "__main__":
    import_main()
