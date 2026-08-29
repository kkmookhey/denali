from pathlib import Path

from denali.connectors.repository_posture import (
    FINDINGS_PLANE,
    RepositoryPostureConnector,
    _bedrock_command_sites,
)
from denali.domain import CoverageState


def test_literal_bedrock_calls_without_guardrail_keys_are_findings(tmp_path: Path) -> None:
    (tmp_path / "calls.ts").write_text(
        "import { BedrockRuntimeClient, ConverseCommand, InvokeModelCommand } "
        "from '@aws-sdk/client-bedrock-runtime';\n"
        "client.send(new ConverseCommand({ modelId, messages: [{ role: 'user', content }] }));\n"
        "client.send(new InvokeModelCommand({\n"
        "  modelId, contentType: 'application/json', body: JSON.stringify({ value: secret }),\n"
        "}));\n"
    )

    batch = RepositoryPostureConnector(
        tmp_path, repository_name="github.com/acme/agent"
    ).collect()

    assert batch.coverage[0].plane == FINDINGS_PLANE
    assert batch.coverage[0].state is CoverageState.COMPLETE
    assert batch.may_resolve_missing
    assert len(batch.findings) == 2
    assert {finding.rule_uid for finding in batch.findings} == {
        "DENALI-REPO-AI-GRD-001"
    }
    assert {finding.evidence.payload["command"] for finding in batch.findings} == {
        "ConverseCommand",
        "InvokeModelCommand",
    }
    assert "secret" not in str(batch.findings)


def test_complete_guardrail_configuration_does_not_emit_findings(tmp_path: Path) -> None:
    (tmp_path / "calls.ts").write_text(
        "import { ConverseCommand as Chat, InvokeModelCommand } "
        "from '@aws-sdk/client-bedrock-runtime';\n"
        "new Chat({ modelId, guardrailConfig, messages });\n"
        "new InvokeModelCommand({ modelId, guardrailIdentifier: id, guardrailVersion: version });\n"
    )

    batch = RepositoryPostureConnector(tmp_path, repository_name="local:safe").collect()

    assert not batch.findings
    assert batch.coverage[0].state is CoverageState.COMPLETE
    assert batch.may_resolve_missing


def test_incomplete_invoke_model_guardrail_configuration_is_distinct(tmp_path: Path) -> None:
    (tmp_path / "call.ts").write_text(
        "import { InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';\n"
        "new InvokeModelCommand({ modelId, guardrailIdentifier: id });\n"
    )

    batch = RepositoryPostureConnector(tmp_path, repository_name="local:incomplete").collect()

    assert batch.findings[0].rule_uid == "DENALI-REPO-AI-GRD-002"
    assert batch.findings[0].evidence.payload["present_guardrail_keys"] == [
        "guardrailIdentifier"
    ]


def test_spread_input_is_partial_and_never_overclaims_absence(tmp_path: Path) -> None:
    (tmp_path / "call.ts").write_text(
        "import { ConverseCommand } from '@aws-sdk/client-bedrock-runtime';\n"
        "new ConverseCommand({ modelId, ...runtimeOptions, messages });\n"
    )

    batch = RepositoryPostureConnector(tmp_path, repository_name="local:spread").collect()

    assert not batch.findings
    assert batch.coverage[0].state is CoverageState.PARTIAL
    assert not batch.may_resolve_missing
    assert "indeterminate" in (batch.coverage[0].detail or "")


def test_non_literal_input_is_partial(tmp_path: Path) -> None:
    (tmp_path / "call.ts").write_text(
        "import { ConverseCommand } from '@aws-sdk/client-bedrock-runtime';\n"
        "new ConverseCommand(commandInput);\n"
    )

    batch = RepositoryPostureConnector(tmp_path, repository_name="local:dynamic").collect()

    assert not batch.findings
    assert batch.coverage[0].state is CoverageState.PARTIAL
    assert "not a literal object" in (batch.coverage[0].detail or "")


def test_nested_guardrail_text_does_not_count_as_top_level_configuration() -> None:
    sites, warnings = _bedrock_command_sites(
        "import { InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';\n"
        "new InvokeModelCommand({ modelId, body: JSON.stringify({ "
        "guardrailIdentifier: 'not-a-command-key' }) });\n",
        "call.ts",
    )

    assert not warnings
    assert sites[0].input_keys == ("body", "modelId")


def test_aliases_share_stable_per_command_ordinals() -> None:
    sites, warnings = _bedrock_command_sites(
        "import { ConverseCommand, ConverseCommand as Chat } "
        "from '@aws-sdk/client-bedrock-runtime';\n"
        "new Chat({ modelId, messages });\n"
        "new ConverseCommand({ modelId, messages });\n",
        "call.ts",
    )

    assert not warnings
    assert [(site.command, site.ordinal) for site in sites] == [
        ("ConverseCommand", 1),
        ("ConverseCommand", 2),
    ]
