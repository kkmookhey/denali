"""Pure issue-correlation rules over a bounded repository snapshot."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import UTC, datetime

from denali.domain import (
    CorrelationAsset,
    CorrelationFinding,
    CorrelationRelationship,
    CorrelationSnapshot,
    CoverageState,
    FindingSeverity,
    IssueCandidate,
    IssueEvaluation,
    IssueFindingLink,
    IssuePathEdge,
    IssuePathNode,
)

RULE_UID = "DENALI-ISSUE-AGENT-WRITE-001"
IDENTITY_SIGNAL = "identity.overprivileged"
TOOL_SIGNAL = "tool.write_without_confirmation"
ELIGIBLE_ASSERTIONS = {"observed", "externally_verified"}
MIN_CONFIDENCE = 0.8


def evaluate_agent_sensitive_write(
    snapshot: CorrelationSnapshot,
    *,
    evaluated_at: datetime | None = None,
) -> IssueEvaluation:
    """Correlate independently supported agent-to-sensitive-data write paths.

    Finding resource references select already observed assets by kind and exact natural
    key. They never add nodes or edges. Only observed or externally verified capability
    relationships with sufficient confidence may participate in the path.
    """

    now = evaluated_at or datetime.now(UTC)
    trusted_assets = tuple(
        asset
        for asset in snapshot.assets
        if asset.assertion_type in ELIGIBLE_ASSERTIONS and asset.confidence >= MIN_CONFIDENCE
    )
    assets_by_id = {asset.id: asset for asset in trusted_assets}
    assets_by_kind_key: dict[tuple[str, str], list[CorrelationAsset]] = defaultdict(list)
    for asset in trusted_assets:
        assets_by_kind_key[(asset.kind, asset.natural_key)].append(asset)

    eligible = tuple(
        relationship
        for relationship in snapshot.relationships
        if relationship.category == "capability"
        and relationship.assertion_type in ELIGIBLE_ASSERTIONS
        and relationship.confidence >= MIN_CONFIDENCE
    )
    by_kind_target: dict[tuple[str, str], list[CorrelationRelationship]] = defaultdict(list)
    by_kind_source: dict[tuple[str, str], list[CorrelationRelationship]] = defaultdict(list)
    for relationship in eligible:
        by_kind_target[(relationship.kind, relationship.target_id)].append(relationship)
        by_kind_source[(relationship.kind, relationship.source_id)].append(relationship)

    identity_findings = _active_signal_findings(snapshot.findings, IDENTITY_SIGNAL)
    tool_findings = _active_signal_findings(snapshot.findings, TOOL_SIGNAL)
    candidates: dict[str, IssueCandidate] = {}
    incomplete = 0
    ambiguous = 0

    for identity_finding in identity_findings:
        identity_assets, identity_ambiguous = _referenced_assets(
            identity_finding, "identity", assets_by_kind_key
        )
        ambiguous += identity_ambiguous
        for tool_finding in tool_findings:
            tool_assets, tool_ambiguous = _referenced_assets(
                tool_finding, "ai_tool", assets_by_kind_key
            )
            ambiguous += tool_ambiguous
            pair_confirmed = False
            for identity in identity_assets:
                for tool in tool_assets:
                    for runs_as in by_kind_target[("runs_as", identity.id)]:
                        agent = assets_by_id.get(runs_as.source_id)
                        if agent is None or agent.kind != "ai_agent":
                            continue
                        invokes = next(
                            (
                                edge
                                for edge in by_kind_source[("can_invoke", agent.id)]
                                if edge.target_id == tool.id
                            ),
                            None,
                        )
                        if invokes is None:
                            continue
                        for writes in by_kind_source[("can_write", tool.id)]:
                            datastore = assets_by_id.get(writes.target_id)
                            if datastore is None or datastore.kind != "ai_datastore":
                                continue
                            if str(datastore.attributes.get("classification", "")).lower() not in {
                                "sensitive",
                                "confidential",
                                "restricted",
                            }:
                                continue
                            candidate = _candidate(
                                identity_finding,
                                tool_finding,
                                agent,
                                identity,
                                tool,
                                datastore,
                                runs_as,
                                invokes,
                                writes,
                            )
                            candidates[candidate.correlation_key] = candidate
                            pair_confirmed = True
            if not pair_confirmed:
                incomplete += 1

    state = CoverageState.COMPLETE
    detail = None
    if incomplete or ambiguous:
        state = CoverageState.UNKNOWN
        detail = (
            f"{incomplete} candidate pairs lacked a confirmed capability path; "
            f"{ambiguous} resource references were ambiguous"
        )
    return IssueEvaluation(
        rule_uid=RULE_UID,
        state=state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates.values(), key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        ambiguous_resource_references=ambiguous,
        detail=detail,
    )


def _active_signal_findings(
    findings: tuple[CorrelationFinding, ...], signal: str
) -> tuple[CorrelationFinding, ...]:
    return tuple(
        finding
        for finding in findings
        if finding.state == "open"
        and finding.evaluation_result == "fail"
        and finding.attributes.get("denali_signal") == signal
    )


def _referenced_assets(
    finding: CorrelationFinding,
    kind: str,
    index: dict[tuple[str, str], list[CorrelationAsset]],
) -> tuple[tuple[CorrelationAsset, ...], int]:
    output: dict[str, CorrelationAsset] = {}
    ambiguous = 0
    for uid in finding.resource_uids:
        matches = index.get((kind, uid), [])
        if len(matches) == 1:
            output[matches[0].id] = matches[0]
        elif len(matches) > 1:
            ambiguous += 1
    return tuple(output.values()), ambiguous


def _candidate(
    identity_finding: CorrelationFinding,
    tool_finding: CorrelationFinding,
    agent: CorrelationAsset,
    identity: CorrelationAsset,
    tool: CorrelationAsset,
    datastore: CorrelationAsset,
    runs_as: CorrelationRelationship,
    invokes: CorrelationRelationship,
    writes: CorrelationRelationship,
) -> IssueCandidate:
    identity_material = "|".join(
        (RULE_UID, agent.natural_key, identity.natural_key, tool.natural_key, datastore.natural_key)
    )
    correlation_key = hashlib.sha256(identity_material.encode()).hexdigest()
    confidence = min(
        agent.confidence,
        identity.confidence,
        tool.confidence,
        datastore.confidence,
        runs_as.confidence,
        invokes.confidence,
        writes.confidence,
    )
    return IssueCandidate(
        correlation_key=correlation_key,
        rule_uid=RULE_UID,
        title=(
            f"{agent.display_name} can change sensitive data through an unconfirmed tool"
        ),
        description=(
            f"{agent.display_name} runs as {identity.display_name}, can invoke "
            f"{tool.display_name}, and that tool can write to {datastore.display_name}. "
            "The execution identity is overprivileged and the write action lacks an "
            "independently enforced confirmation step."
        ),
        risk=(
            "A manipulated prompt or tool request can cross a confirmed authorization "
            "path and make persistent changes to sensitive data."
        ),
        remediation=(
            "Constrain the execution identity, require confirmation at the write-tool "
            "boundary, and restrict the tool to the exact datastore operations required."
        ),
        severity=FindingSeverity.CRITICAL,
        confidence=confidence,
        findings=(
            IssueFindingLink(identity_finding.id, "overprivileged_execution_identity"),
            IssueFindingLink(tool_finding.id, "unconfirmed_write_tool"),
        ),
        path_nodes=(
            IssuePathNode(agent.id, 0, "agent"),
            IssuePathNode(identity.id, 1, "execution_identity"),
            IssuePathNode(tool.id, 2, "write_tool"),
            IssuePathNode(datastore.id, 3, "sensitive_data"),
        ),
        path_edges=(
            IssuePathEdge(runs_as.id, 0),
            IssuePathEdge(invokes.id, 1),
            IssuePathEdge(writes.id, 2),
        ),
        attributes={
            "correlation": "deterministic",
            "path_status": "confirmed",
            "finding_count": 2,
            "capability_edge_count": 3,
        },
    )
