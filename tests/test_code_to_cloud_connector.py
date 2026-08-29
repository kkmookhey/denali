from pathlib import Path

from denali.connectors.code_to_cloud import (
    CodeToCloudConnector,
    DeploymentTarget,
    _deployment_declarations,
    _local_imports,
    _local_module_graph,
)
from denali.domain import AssertionType, CoverageState, RelationshipKind

SOURCE = """
const fn = new nodejs.NodejsFunction(this, 'AgentFn', {
  functionName: 'ni-sales-agent',
  entry: 'src/handler.ts',
});
const task = new ecs.FargateTaskDefinition(this, 'ProposalWorkerTask', {});
const containerName = 'proposal-worker';
task.addContainer('ProposalWorkerContainer', {
  containerName,
  image: ecs.ContainerImage.fromAsset('.', { file: 'src/worker/Dockerfile' }),
});
"""


def target(
    *,
    natural_key: str,
    display_name: str,
    service: str,
    logical_id: str,
    containers=(),
    deployment_artifact=None,
) -> DeploymentTarget:
    return DeploymentTarget(
        natural_key=natural_key,
        display_name=display_name,
        service=service,
        logical_id=logical_id,
        evidence_locator=f"aws://fixture/{natural_key}",
        evidence_payload={
            "container_names": list(containers),
            **({"deployment_artifact": deployment_artifact} if deployment_artifact else {}),
        },
    )


def write_artifact_fixture(root: Path) -> None:
    (root / "package.json").write_text("{}")
    (root / "src" / "worker").mkdir(parents=True)
    (root / "src" / "shared.ts").write_text("export const shared = true;\n")
    (root / "src" / "handler.ts").write_text(
        "import { shared } from './shared.js';\nexport const handler = () => shared;\n"
    )
    (root / "src" / "worker" / "main.ts").write_text(
        "import { shared } from '../shared.js';\nvoid shared;\n"
    )
    (root / "src" / "worker" / "Dockerfile").write_text(
        "FROM node:24 AS build\n"
        "RUN esbuild src/worker/main.ts \\\n"
        "    --bundle --platform=node --outfile=dist/worker.cjs\n"
    )


def write_cdk_manifest(root: Path) -> None:
    output = root / "cdk.out"
    output.mkdir()
    (output / "Stack.assets.json").write_text(
        """
{
  "version": "54.0.0",
  "files": {
    "lambda-asset": {
      "displayName": "AgentFn/Code",
      "source": {"path": "asset.lambda-asset", "packaging": "zip"},
      "destinations": {
        "fixture": {"bucketName": "cdk-assets", "objectKey": "lambda-asset.zip"}
      }
    }
  },
  "dockerImages": {
    "worker-asset": {
      "displayName": "ProposalWorkerTask/Container/AssetImage",
      "source": {"directory": "asset.worker-asset", "dockerFile": "src/worker/Dockerfile"},
      "destinations": {
        "fixture": {"repositoryName": "worker", "imageTag": "worker-asset"}
      }
    }
  }
}
"""
    )


def test_discovers_literal_lambda_and_ecs_declarations() -> None:
    declarations, warnings = _deployment_declarations(SOURCE, "infra/stack.ts")

    assert warnings == []
    assert [(item.service, item.construct_id, item.deployment_name) for item in declarations] == [
        ("lambda", "AgentFn", "ni-sales-agent"),
        ("ecs", "ProposalWorkerTask", "proposal-worker"),
    ]
    assert declarations[0].entry == "src/handler.ts"
    assert declarations[1].build_context == "."
    assert declarations[1].build_file == "src/worker/Dockerfile"


def test_task_parser_does_not_borrow_a_later_tasks_container() -> None:
    source = """
const first = new ecs.FargateTaskDefinition(this, 'FirstTask', {});
const second = new ecs.FargateTaskDefinition(this, 'SecondTask', {});
second.addContainer('Worker', {
  containerName: 'second-worker',
});
"""

    declarations, warnings = _deployment_declarations(source, "infra/stack.ts")

    assert [(item.construct_id, item.deployment_name) for item in declarations] == [
        ("SecondTask", "second-worker")
    ]
    assert "FirstTask" not in " ".join(warnings)
    assert "task container declaration not found" in warnings[0]


def test_commented_deployments_and_literal_properties_are_not_evidence() -> None:
    source = """
// new nodejs.NodejsFunction(this, 'DisabledFn', {
//   functionName: 'disabled',
//   entry: 'src/disabled.ts',
// });
new nodejs.NodejsFunction(this, 'DynamicFn', {
  // functionName: 'not-real',
  functionName: configuredName,
  entry: 'src/handler.ts',
});
"""

    declarations, warnings = _deployment_declarations(source, "infra/stack.ts")

    assert declarations == []
    assert len(warnings) == 1
    assert "Lambda functionName is not literal" in warnings[0]


def test_exact_independent_identifiers_create_deployed_by_edges(tmp_path: Path) -> None:
    (tmp_path / "stack.ts").write_text(SOURCE)
    write_artifact_fixture(tmp_path)
    targets = (
        target(
            natural_key="arn:aws:lambda:region:account:function:ni-sales-agent",
            display_name="ni-sales-agent",
            service="lambda",
            logical_id="AgentFnC1FD126F",
        ),
        target(
            natural_key="arn:aws:ecs:region:account:task-definition/worker:10",
            display_name="worker",
            service="ecs",
            logical_id="ProposalWorkerTask0422E6B9",
            containers=("proposal-worker",),
        ),
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/anna",
        targets=targets,
    ).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    assert len(batch.relationships) == 2
    assert {item.kind for item in batch.relationships} == {RelationshipKind.DEPLOYED_BY}
    assert {item.assertion_type for item in batch.relationships} == {AssertionType.INFERRED}
    assert all(item.confidence == 1.0 for item in batch.relationships)
    assert all(item.target.natural_key == "github.com/example/anna" for item in batch.relationships)
    assert "control_plane_evidence" in batch.relationships[0].evidence.payload
    by_service = {item.attributes["service"]: item for item in batch.relationships}
    assert by_service["lambda"].attributes["entry"] == "src/handler.ts"
    assert by_service["lambda"].attributes["reachable_source_paths"] == [
        "src/handler.ts",
        "src/shared.ts",
    ]
    assert by_service["ecs"].attributes["entry"] == "src/worker/main.ts"
    assert by_service["ecs"].attributes["build_file"] == "src/worker/Dockerfile"
    assert by_service["ecs"].attributes["artifact_import_chains"]["src/shared.ts"] == [
        "src/worker/main.ts",
        "src/shared.ts",
    ]
    assert by_service["lambda"].attributes["artifact_identity_status"] == "not_evaluated"
    assert by_service["lambda"].attributes["source_revision_status"] == "unattested"


def test_exact_cdk_locator_match_is_separate_from_unattested_revision(tmp_path: Path) -> None:
    (tmp_path / "stack.ts").write_text(SOURCE)
    write_artifact_fixture(tmp_path)
    write_cdk_manifest(tmp_path)
    targets = (
        target(
            natural_key="arn:aws:lambda:region:account:function:ni-sales-agent",
            display_name="ni-sales-agent",
            service="lambda",
            logical_id="AgentFnC1FD126F",
            deployment_artifact={
                "kind": "s3_object",
                "bucket": "cdk-assets",
                "key": "lambda-asset.zip",
                "code_sha256": "live-code-sha",
            },
        ),
        target(
            natural_key="arn:aws:ecs:region:account:task-definition/worker:10",
            display_name="worker",
            service="ecs",
            logical_id="ProposalWorkerTask0422E6B9",
            containers=("proposal-worker",),
            deployment_artifact={
                "kind": "container_image",
                "container_name": "proposal-worker",
                "image": "123.dkr.ecr/worker:worker-asset",
            },
        ),
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/anna",
        targets=targets,
    ).collect()

    by_service = {item.attributes["service"]: item for item in batch.relationships}
    for relationship in by_service.values():
        assert relationship.attributes["artifact_identity_status"] == "matched"
        assert relationship.attributes["artifact_identity_method"] == "cdk_asset_manifest"
        assert relationship.attributes["source_revision_status"] == "unattested"
        assert relationship.attributes["repository_revision"] == "working-tree"
    assert by_service["lambda"].attributes["deployment_asset_id"] == "lambda-asset"
    assert by_service["ecs"].attributes["deployment_asset_id"] == "worker-asset"


def test_manifest_without_exact_locator_is_not_reported_as_drift(tmp_path: Path) -> None:
    (tmp_path / "stack.ts").write_text(SOURCE.split("const task", 1)[0])
    write_artifact_fixture(tmp_path)
    write_cdk_manifest(tmp_path)
    matching = target(
        natural_key="arn:aws:lambda:region:account:function:ni-sales-agent",
        display_name="ni-sales-agent",
        service="lambda",
        logical_id="AgentFnC1FD126F",
        deployment_artifact={
            "kind": "s3_object",
            "bucket": "different-bucket",
            "key": "different-key.zip",
        },
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/anna",
        targets=(matching,),
    ).collect()

    relationship = batch.relationships[0]
    assert relationship.attributes["artifact_identity_status"] == "not_matched"
    assert relationship.attributes["source_revision_status"] == "unattested"
    assert "drift" not in str(relationship.attributes).lower()


def test_module_graph_includes_literal_dynamic_imports_but_not_type_only_imports() -> None:
    sources = {
        "src/entry.ts": (
            "import type { TypeOnly } from './types.js';\n"
            "// import './commented.js';\n"
            "export async function load() { return import('./runtime.js'); }\n"
        ),
        "src/types.ts": "export interface TypeOnly { value: string }\n",
        "src/commented.ts": "export const ignored = true;\n",
        "src/runtime.ts": "export const runtime = true;\n",
    }

    reachable, chains, warnings = _local_module_graph("src/entry.ts", sources)

    assert warnings == []
    assert reachable == {"src/entry.ts", "src/runtime.ts"}
    assert chains["src/runtime.ts"] == ["src/entry.ts", "src/runtime.ts"]
    assert _local_imports(sources["src/entry.ts"]) == ("./runtime.js",)


def test_unresolved_local_import_is_partial_without_inventing_a_module(tmp_path: Path) -> None:
    source = SOURCE.split("const task", 1)[0]
    (tmp_path / "stack.ts").write_text(source)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "handler.ts").write_text("import './missing.js';\n")
    matching = target(
        natural_key="arn:aws:lambda:region:account:function:ni-sales-agent",
        display_name="ni-sales-agent",
        service="lambda",
        logical_id="AgentFnABC123",
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/anna",
        targets=(matching,),
    ).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert batch.relationships[0].attributes["reachable_source_paths"] == ["src/handler.ts"]
    assert "local import './missing.js' was not found" in (batch.coverage[0].detail or "")


def test_model_or_name_only_match_does_not_create_a_deployment_edge(tmp_path: Path) -> None:
    (tmp_path / "stack.ts").write_text(SOURCE)
    wrong_logical_id = target(
        natural_key="arn:aws:lambda:region:account:function:ni-sales-agent",
        display_name="ni-sales-agent",
        service="lambda",
        logical_id="DifferentFunctionABC123",
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/anna",
        targets=(wrong_logical_id,),
    ).collect()

    assert batch.relationships == ()


def test_ambiguous_matches_are_visible_and_not_correlated(tmp_path: Path) -> None:
    (tmp_path / "stack.ts").write_text(SOURCE.split("const task", 1)[0])
    matching = target(
        natural_key="arn:aws:lambda:region:account:function:ni-sales-agent",
        display_name="ni-sales-agent",
        service="lambda",
        logical_id="AgentFnABC123",
    )
    second = target(
        natural_key="arn:aws:lambda:other:account:function:ni-sales-agent",
        display_name="ni-sales-agent",
        service="lambda",
        logical_id="AgentFnXYZ789",
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/anna",
        targets=(matching, second),
    ).collect()

    assert batch.relationships == ()
    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert "matched multiple active workloads" in (batch.coverage[0].detail or "")
