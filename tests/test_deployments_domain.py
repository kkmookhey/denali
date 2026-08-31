import pytest

from denali.domain import (
    DeploymentIdentifier,
    DeploymentIdentity,
    IdentifierComparison,
)


def test_provider_neutral_identity_requires_boundary_and_all_identifiers() -> None:
    declared = DeploymentIdentity(
        provider="gcp",
        runtime_kind="container_service",
        identifiers=(
            DeploymentIdentifier("project", "denali-test"),
            DeploymentIdentifier("location", "us-central1"),
            DeploymentIdentifier("service_name", "denali-ai"),
        ),
    )
    observed = DeploymentIdentity(
        provider="gcp",
        runtime_kind="container_service",
        identifiers=(
            DeploymentIdentifier("project", "denali-test"),
            DeploymentIdentifier("location", "us-central1"),
            DeploymentIdentifier("service_name", "denali-ai"),
            DeploymentIdentifier("revision", "denali-ai-00001-abc"),
        ),
    )

    assert declared.matches(observed)
    assert not DeploymentIdentity(
        provider="azure",
        runtime_kind="container_service",
        identifiers=declared.identifiers,
    ).matches(observed)


def test_prefix_comparison_is_explicit_and_round_trips() -> None:
    declared = DeploymentIdentity(
        provider="aws",
        runtime_kind="serverless_function",
        identifiers=(
            DeploymentIdentifier(
                "cloudformation_logical_id",
                "AgentFn",
                comparison=IdentifierComparison.PREFIX,
                evidence_basis="cloudformation_logical_id_prefix",
            ),
        ),
    )
    observed = DeploymentIdentity(
        provider="aws",
        runtime_kind="serverless_function",
        identifiers=(DeploymentIdentifier("cloudformation_logical_id", "AgentFnABC123"),),
    )

    assert declared.matches(observed)
    assert DeploymentIdentity.from_record(declared.to_record()) == declared
    assert declared.match_basis() == ["cloudformation_logical_id_prefix"]


@pytest.mark.parametrize("provider,runtime", [("", "function"), ("gcp", "")])
def test_identity_rejects_empty_boundaries(provider: str, runtime: str) -> None:
    with pytest.raises(ValueError):
        DeploymentIdentity(
            provider=provider,
            runtime_kind=runtime,
            identifiers=(DeploymentIdentifier("service_name", "denali-ai"),),
        )
