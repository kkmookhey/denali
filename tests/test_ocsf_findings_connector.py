from __future__ import annotations

from denali.connectors.ocsf_findings import (
    FINDINGS_PLANE,
    OcsfFindingConnector,
    derive_report_identity,
)
from denali.domain import CoverageState, EvaluationResult, FindingSeverity, FindingState


def prowler_record(
    *,
    uid: str = "prowler-aws-bedrock_guardrail_prompt_attack-123-us-east-1-gr-1",
    status_code: str = "FAIL",
) -> dict:
    return {
        "message": "source message may include sensitive values",
        "metadata": {
            "event_code": "bedrock_guardrail_prompt_attack",
            "product": {
                "name": "Prowler",
                "uid": "prowler",
                "vendor_name": "Prowler",
                "version": "5.3.0",
            },
            "version": "1.3.0",
        },
        "severity_id": 5,
        "severity": "Critical",
        "status": "New",
        "status_code": status_code,
        "status_detail": "do not persist this result-specific secret SECRET-123",
        "finding_info": {
            "uid": uid,
            "title": "Bedrock guardrail should block prompt attacks",
            "desc": "Checks the configured guardrail policy.",
            "types": ["Protect", "AI Security"],
        },
        "resources": [
            {
                "uid": "arn:aws:bedrock:us-east-1:123456789012:guardrail/gr-1",
                "name": "customer-safety",
                "type": "AwsBedrockGuardrail",
                "region": "us-east-1",
                "data": {
                    "metadata": {
                        "api_key": "SECRET-RESOURCE-VALUE",
                        "blockedInputMessaging": "customer-private-message",
                    }
                },
            }
        ],
        "cloud": {
            "provider": "aws",
            "region": "us-east-1",
            "account": {"uid": "123456789012"},
        },
        "remediation": {
            "desc": "Enable the prompt attack filter.",
            "references": ["https://docs.aws.amazon.com/bedrock/"],
        },
        "risk_details": "An attacker may manipulate model behavior.",
        "unmapped": {
            "categories": ["ai-security"],
            "compliance": {"OWASP-LLM": ["LLM01"]},
        },
        "time": 1_767_225_600,
        "class_name": "Detection Finding",
        "class_uid": 2004,
    }


def collect(records: list) -> object:
    return OcsfFindingConnector().collect(
        records,
        connection_id="prowler-aws-audit",
        run_id="scan-1",
        scope_key="provider=aws,account=123456789012",
        source_locator="file:///tmp/prowler.ocsf.json",
    )


def test_prowler_fail_is_normalized_without_copying_arbitrary_resource_data() -> None:
    batch = collect([prowler_record()])

    assert batch.coverage[0].state is CoverageState.COMPLETE
    finding = batch.findings[0]
    assert finding.severity is FindingSeverity.CRITICAL
    assert finding.state is FindingState.OPEN
    assert finding.evaluation_result is EvaluationResult.FAIL
    assert finding.rule_uid == "bedrock_guardrail_prompt_attack"
    assert finding.affected_resources[0].uid.endswith("guardrail/gr-1")
    assert finding.compliance == {"OWASP-LLM": ("LLM01",)}
    serialized = str(finding)
    assert "SECRET-123" not in serialized
    assert "SECRET-RESOURCE-VALUE" not in serialized
    assert "customer-private-message" not in serialized
    assert finding.evidence.payload["record_sha256"]


def test_prowler_pass_explicitly_resolves_the_same_source_finding() -> None:
    batch = collect([prowler_record(status_code="PASS")])

    finding = batch.findings[0]
    assert finding.state is FindingState.RESOLVED
    assert finding.evaluation_result is EvaluationResult.PASS


def test_bad_sibling_makes_coverage_partial_without_hiding_valid_findings() -> None:
    batch = collect([prowler_record(), {"class_uid": 2004}])

    assert len(batch.findings) == 1
    assert batch.coverage[0].plane == FINDINGS_PLANE
    assert batch.coverage[0].state is CoverageState.PARTIAL
    assert "item 1: missing finding_info object" in (batch.coverage[0].detail or "")


def test_all_invalid_records_fail_coverage_and_duplicate_ids_are_partial() -> None:
    failed = collect(["not-an-object"])
    assert failed.coverage[0].state is CoverageState.FAILED

    duplicate = collect([prowler_record(), prowler_record()])
    assert len(duplicate.findings) == 1
    assert duplicate.coverage[0].state is CoverageState.PARTIAL


def test_report_identity_is_stable_for_one_product_and_account() -> None:
    identity = derive_report_identity([prowler_record()])

    assert identity == {
        "scope_key": "provider=aws,account=123456789012",
        "connection_id": "ocsf:prowler:aws:123456789012",
    }
