"""Evidence-backed posture checks for AI invocation call sites in source repositories.

This connector performs deliberately narrow static analysis. It reports what a literal
AWS SDK command input requests at a source location; it does not claim that application
prompts are exploitable or that middleware and downstream controls do not exist.
"""

from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from denali.connectors.repository import MAX_SOURCE_BYTES, RepositoryConnector, _source_files
from denali.domain import (
    AffectedResource,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    EvaluationResult,
    Evidence,
    FindingAssertion,
    FindingBatch,
    FindingSeverity,
    FindingState,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.repository_posture"
CAPABILITIES = ConnectorCapabilities(findings=True)
FINDINGS_PLANE = "repository_ai_configuration_findings"

_SUPPORTED_COMMANDS = {
    "ConverseCommand": ("guardrailConfig",),
    "ConverseStreamCommand": ("guardrailConfig",),
    "InvokeModelCommand": ("guardrailIdentifier", "guardrailVersion"),
    "InvokeModelWithResponseStreamCommand": (
        "guardrailIdentifier",
        "guardrailVersion",
    ),
}
_IMPORT_RE = re.compile(
    r"import\s*\{(?P<names>.*?)\}\s*from\s*[\"']@aws-sdk/client-bedrock-runtime[\"']",
    re.DOTALL,
)
_COMMAND_RE_TEMPLATE = r"\bnew\s+{alias}\s*\("
_PROPERTY_RE = re.compile(r"(?:^|,)\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*:")
_SHORTHAND_RE = re.compile(
    r"(?:^|,)\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*(?=,|$)"
)
_SPREAD_RE = re.compile(r"(?:^|,)\s*\.\.\.")


@dataclass(frozen=True, slots=True)
class CommandSite:
    command: str
    path: str
    line: int
    ordinal: int
    input_keys: tuple[str, ...]
    has_spread: bool

    @property
    def identity(self) -> str:
        return f"{self.path}:{self.command}:{self.ordinal}"


class RepositoryPostureConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(
        self,
        root: Path,
        *,
        repository_name: str | None = None,
        app_id: str | None = None,
    ) -> None:
        metadata = RepositoryConnector(
            root, repository_name=repository_name, app_id=app_id
        )
        self.root = metadata.root
        self.repository_name = metadata.repository_name
        self.commit = metadata.commit
        self.dirty = metadata.dirty
        self.revision = metadata.revision

    def collect(self, *, connection_id: str | None = None) -> FindingBatch:
        observed_at = datetime.now(UTC)
        connection = connection_id or self.repository_name
        scope = f"repository:{self.repository_name}"
        run_id = f"repo-posture-{self.revision[:18]}-{observed_at.isoformat()}"
        warnings: list[str] = []
        sites: list[CommandSite] = []

        for source_file in _source_files(self.root):
            relative = source_file.relative_to(self.root).as_posix()
            try:
                if source_file.stat().st_size > MAX_SOURCE_BYTES:
                    warnings.append(f"{relative}: larger than {MAX_SOURCE_BYTES} bytes")
                    continue
                text = source_file.read_text(encoding="utf-8", errors="replace")
            except OSError as error:
                warnings.append(f"{relative}: {error.__class__.__name__}")
                continue
            discovered, file_warnings = _bedrock_command_sites(text, relative)
            sites.extend(discovered)
            warnings.extend(file_warnings)

        findings: list[FindingAssertion] = []
        for site in sites:
            required = _SUPPORTED_COMMANDS[site.command]
            present = tuple(key for key in required if key in site.input_keys)
            if len(present) == len(required):
                continue
            if site.has_spread:
                warnings.append(
                    f"{site.path}:{site.line}: {site.command} input uses a spread; "
                    "guardrail configuration is indeterminate"
                )
                continue
            findings.append(self._guardrail_finding(site, required, present, observed_at))

        state = CoverageState.PARTIAL if warnings else CoverageState.COMPLETE
        detail = "; ".join(dict.fromkeys(warnings))[:4_000] if warnings else None
        return FindingBatch(
            connector_id=self.connector_id,
            connection_id=connection,
            run_id=run_id,
            scope_key=scope,
            collected_at=observed_at,
            coverage=(Coverage(FINDINGS_PLANE, state, scope, detail),),
            findings=tuple(findings),
            authoritative=True,
        )

    def _guardrail_finding(
        self,
        site: CommandSite,
        required: tuple[str, ...],
        present: tuple[str, ...],
        observed_at: datetime,
    ) -> FindingAssertion:
        absent = not present
        title = (
            f"{site.command} call does not request an AWS managed guardrail"
            if absent
            else f"{site.command} call has incomplete AWS managed-guardrail configuration"
        )
        expected = (
            "guardrailConfig"
            if site.command.startswith("Converse")
            else "guardrailIdentifier and guardrailVersion"
        )
        return FindingAssertion(
            source_uid=f"{self.repository_name}:{site.identity}:managed-guardrail",
            rule_uid=(
                "DENALI-REPO-AI-GRD-001" if absent else "DENALI-REPO-AI-GRD-002"
            ),
            title=title,
            description=(
                f"The literal {site.command} input at {site.path}:{site.line} does not contain "
                f"{expected}. Denali inspected the command input keys, not prompt text or runtime "
                "payload values. This does not establish whether custom SDK middleware or a "
                "downstream proxy adds an equivalent control."
            ),
            risk=(
                "This source call site does not itself request provider-managed filtering for "
                "prompt attacks or configured content categories. Application-layer instructions "
                "and validation may reduce risk, but they are separate controls."
            ),
            remediation=(
                f"Pass {expected} in this {site.command} input, sourcing identifiers through the "
                "deployment configuration. Test the selected guardrail version against this "
                "call site's expected inputs and outputs before enforcement."
            ),
            remediation_references=(),
            severity=FindingSeverity.MEDIUM,
            state=FindingState.OPEN,
            evaluation_result=EvaluationResult.FAIL,
            class_uid=2003,
            class_name="Compliance Finding",
            observed_at=observed_at,
            evidence=Evidence(
                source_type="static_source_analysis",
                locator=f"repo://{self.repository_name}/{site.path}#L{site.line}",
                observed_at=observed_at,
                payload={
                    "command": site.command,
                    "input_keys": list(site.input_keys),
                    "required_guardrail_keys": list(required),
                    "present_guardrail_keys": list(present),
                    "evaluation": (
                        "managed_guardrail_keys_absent"
                        if absent
                        else "managed_guardrail_keys_incomplete"
                    ),
                    "repository_revision": self.revision,
                },
            ),
            affected_resources=(
                AffectedResource(
                    uid=f"repo://{self.repository_name}/{site.identity}",
                    name=f"{site.path}:{site.line}",
                    resource_type="Bedrock SDK Call Site",
                    provider="Git",
                ),
            ),
            attributes={
                "category": "AI Configuration",
                "product": "Denali Repository Posture",
                "service": "bedrock-runtime",
                "denali_signal": "repository.bedrock_managed_guardrail_not_requested",
                "repository": self.repository_name,
                "repository_revision": self.revision,
                "source_path": site.path,
                "source_line": site.line,
            },
        )


def _bedrock_command_sites(text: str, relative: str) -> tuple[list[CommandSite], list[str]]:
    aliases = _bedrock_import_aliases(text)
    warnings: list[str] = []
    sites: list[CommandSite] = []
    if "@aws-sdk/client-bedrock-runtime" in text and not aliases and re.search(
        r"\bnew\s+(?:Converse|InvokeModel)\w*Command\s*\(", text
    ):
        return [], [f"{relative}: unsupported Bedrock Runtime import form"]

    occurrences: list[tuple[int, str, str, re.Match[str]]] = []
    for alias, command in aliases.items():
        pattern = re.compile(_COMMAND_RE_TEMPLATE.format(alias=re.escape(alias)))
        occurrences.extend(
            (match.start(), alias, command, match) for match in pattern.finditer(text)
        )
    ordinals: dict[str, int] = {}
    for _, _, command, match in sorted(occurrences, key=lambda item: item[0]):
        ordinals[command] = ordinals.get(command, 0) + 1
        ordinal = ordinals[command]
        argument_start = _skip_space_and_comments(text, match.end())
        if argument_start >= len(text) or text[argument_start] != "{":
            warnings.append(
                f"{relative}:{_line(text, match.start())}: {command} input is not a "
                "literal object"
            )
            continue
        object_end = _balanced_object_end(text, argument_start)
        if object_end is None:
            warnings.append(
                f"{relative}:{_line(text, match.start())}: unbalanced {command} input"
            )
            continue
        view = _top_level_object_view(text[argument_start : object_end + 1])
        input_keys = set(_PROPERTY_RE.findall(view)) | set(_SHORTHAND_RE.findall(view))
        sites.append(
            CommandSite(
                command=command,
                path=relative,
                line=_line(text, match.start()),
                ordinal=ordinal,
                input_keys=tuple(sorted(input_keys)),
                has_spread=bool(_SPREAD_RE.search(view)),
            )
        )
    return sites, warnings


def _bedrock_import_aliases(text: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for match in _IMPORT_RE.finditer(text):
        for item in match.group("names").split(","):
            parts = re.split(r"\s+as\s+", item.strip())
            original = parts[0].strip()
            alias = parts[1].strip() if len(parts) == 2 else original
            if original in _SUPPORTED_COMMANDS and re.fullmatch(
                r"[A-Za-z_$][A-Za-z0-9_$]*", alias
            ):
                aliases[alias] = original
    return aliases


def _skip_space_and_comments(text: str, start: int) -> int:
    index = start
    while index < len(text):
        if text[index].isspace():
            index += 1
        elif text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline + 1
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = len(text) if end < 0 else end + 2
        else:
            break
    return index


def _balanced_object_end(text: str, start: int) -> int | None:
    depth = 0
    state = "code"
    escaped = False
    index = start
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state in {"single", "double", "template"}:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "single" and char == "'") or (
                state == "double" and char == '"'
            ) or (state == "template" and char == "`"):
                state = "code"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and nxt == "/":
                state = "code"
                index += 1
        elif char == "/" and nxt == "/":
            state = "line_comment"
            index += 1
        elif char == "/" and nxt == "*":
            state = "block_comment"
            index += 1
        elif char == "'":
            state = "single"
        elif char == '"':
            state = "double"
        elif char == "`":
            state = "template"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _top_level_object_view(text: str) -> str:
    output: list[str] = []
    curly = square = paren = 0
    state = "code"
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        base = curly == 1 and square == 0 and paren == 0
        if state in {"single", "double", "template"}:
            output.append(" ")
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "single" and char == "'") or (
                state == "double" and char == '"'
            ) or (state == "template" and char == "`"):
                state = "code"
        elif state == "line_comment":
            output.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            output.append(" ")
            if char == "*" and nxt == "/":
                output.append(" ")
                state = "code"
                index += 1
        elif char == "/" and nxt in {"/", "*"}:
            output.extend((" ", " "))
            state = "line_comment" if nxt == "/" else "block_comment"
            index += 1
        elif char in {"'", '"', "`"}:
            output.append(" ")
            state = {"'": "single", '"': "double", "`": "template"}[char]
        else:
            output.append(char if base and not (char == "}" and curly == 1) else " ")
            if char == "{":
                curly += 1
            elif char == "}":
                curly -= 1
            elif char == "[":
                square += 1
            elif char == "]":
                square -= 1
            elif char == "(":
                paren += 1
            elif char == ")":
                paren -= 1
        index += 1
    return "".join(output)


def _line(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def scan_main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate AI call sites in a repository")
    parser.add_argument("path", type=Path, help="repository root")
    parser.add_argument("--repository-name", help="canonical repository name")
    parser.add_argument("--app-id", help="stable application namespace")
    parser.add_argument("--connection-id", help="source connection id")
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"),
    )
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    args = parser.parse_args()
    if not args.dsn:
        raise SystemExit("--dsn or DENALI_DSN is required")
    connector = RepositoryPostureConnector(
        args.path,
        repository_name=args.repository_name,
        app_id=args.app_id,
    )
    batch = connector.collect(connection_id=args.connection_id)
    migrate(args.dsn)
    result = PostgresInventoryRepository(args.dsn).ingest_findings(args.tenant_id, batch)
    print(
        f"Evaluated repository {connector.repository_name}: "
        f"{result['findings']} open findings, {result['resolved_missing']} resolved by absence; "
        f"coverage={batch.coverage[0].state.value}"
    )
    if batch.coverage[0].state is not CoverageState.COMPLETE:
        raise SystemExit(2)
