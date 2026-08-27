# Denali

Denali is an independent, open-source AI security platform.

Its job is to discover AI systems, explain what they can do, show the evidence behind
every claim, and correlate AI posture with identity, cloud, code, data, vulnerability,
and runtime context.

Denali integrates with CSPMs; it is not an extension of one. Prowler is the first
reference CSPM integration. OCSF is the interchange format for findings and activity,
while Denali owns a richer canonical model for durable inventory and relationships.

## Product sequence

1. **Inventory** — agents, models, MCP servers, tools, guardrails, pipelines, data,
   workloads, repositories, and identities.
2. **Findings** — atomic configuration, model, code, identity, and vulnerability facts.
3. **Issues** — correlated, evidence-bearing attack paths.
4. **Threats** — observed runtime behavior and investigations.

The first public milestone is **Denali Inventory Preview**. Its definition is in
[`docs/product/inventory-preview.md`](docs/product/inventory-preview.md).

## Repository status

This repository is intentionally new. Proven first-party components will be imported
from the CISOBrief history only after they conform to Denali's standalone contracts.
Shasta infrastructure and Prowler UI patches will not be carried forward.

The foundation currently contains the canonical inventory and connector contracts, a
Postgres assertion store, and the first read/write inventory API. A transparent demo
connector provides fixture data for local product development; every fixture assertion
is visibly identified as such in its evidence.

## Development

Requires Python 3.11 or newer and Docker for the runnable stack.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[api,aws,dev]'
docker compose up -d --build
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali denali-demo-seed
```

The Denali web application is then available at <http://127.0.0.1:3080>. The API
remains available at <http://127.0.0.1:8088>, with interactive documentation at
<http://127.0.0.1:8088/docs>. The local stack deliberately uses ports `3080`, `8088`,
and `55450` to avoid colliding with the earlier CISOBrief development environment.

Scan a source repository into Denali with the first-party repository connector:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-repo-scan /path/to/repository --app-id your-application
```

The connector discovers AI frameworks, model-provider references, MCP servers, and MCP
tools without executing repository code. It excludes tests, fixtures, generated or
vendored directories, and symlinked source files. Evidence snippets are secret-redacted;
read or parse failures mark coverage partial so an incomplete scan cannot withdraw
previously observed assets.

Observe a running MCP Streamable HTTP server without invoking any tools:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-mcp-observe https://mcp.example.com/mcp --app-id your-application
```

For authenticated servers, place the bearer token in `DENALI_MCP_BEARER_TOKEN`; Denali
never accepts it as a command-line value or writes it to evidence. The observer performs
MCP initialization and paginated `tools/list` only. Cleartext HTTP is restricted to
loopback hosts unless explicitly overridden.

Discover native AWS Bedrock inventory using the normal AWS credential chain or a named
profile:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-aws-scan --regions us-east-1,us-west-2 --profile security-audit
```

The phase-one AWS connector uses read-only `ListAgents`, `GetAgent`, `ListGuardrails`,
and `GetGuardrail` calls. It discovers agents, their referenced foundation models,
execution roles, guardrails, and the evidence-backed relationships between them. Each
region and API family has an independent coverage boundary, so a failed guardrail read
cannot erase agents and a partial scan cannot withdraw prior inventory. "Complete"
means complete within the AWS principal's visibility; Denali cannot prove that an IAM
policy did not filter resources outside that visibility. Grant `bedrock:ListAgents`,
`bedrock:GetAgent`, `bedrock:ListGuardrails`, and `bedrock:GetGuardrail` in every region
you intend to scan.

Raw agent instructions, guardrail blocked messages, topic names, and regex patterns are
not persisted. Denali stores configuration presence, normalized policy types and counts,
and an instruction hash and length so posture can be evaluated without copying sensitive
prompt content.

Import findings from a Prowler JSON-OCSF report—or another producer that emits an OCSF
Findings class—with:

```bash
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  denali-ocsf-import ./output/prowler-output.ocsf.json \
  --connection-id prowler-production-aws
```

The importer deliberately does not turn an OCSF resource reference into a Denali asset
or graph edge. It stores a finding, normalized affected-resource references, compliance
mappings, and an evidence hash. Arbitrary `resources.data` content is never persisted;
Prowler reports can contain sensitive configuration values in that field. Imports are
additive by default. Pass `--authoritative` only for a complete, unfiltered report when
absence should resolve findings from the same connection and scope. A partial or failed
import can never resolve findings by absence.

The read API exposes `/v1/findings`, `/v1/findings/summary`, and
`/v1/findings/{finding_id}`. The independent Denali findings UI will arrive with the
configuration-findings milestone; this boundary is intentionally usable before that UI.

Run the fast suite and the explicit Postgres contract gate with:

```bash
pytest
DENALI_TEST_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  pytest -q tests/test_inventory_postgres.py
```

The fast suite skips rather than disguises the Postgres integration tests when
`DENALI_TEST_DSN` is absent.

## Principles

- Evidence before inference.
- Deterministic security decisions; AI assists and explains.
- Declared, inferred, observed, and externally verified are different claims.
- Capability is not influence.
- Agent identity is not execution-principal identity.
- A failed or partial collection can never withdraw previously known inventory.
- Unknown coverage is visible; it never renders as zero risk.
- Every integration declares whether it provides findings, inventory, relationships,
  activity, or only a subset.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
