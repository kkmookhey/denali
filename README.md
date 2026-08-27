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
python -m pip install -e '.[api,dev]'
docker compose up -d --build
DENALI_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali denali-demo-seed
```

The API is then available at <http://127.0.0.1:8088>, with interactive documentation at
<http://127.0.0.1:8088/docs>. The local stack deliberately uses ports `8088` and `55450`
to avoid colliding with the earlier CISOBrief development environment.

Run the fast suite and the explicit Postgres contract gate with:

```bash
pytest
DENALI_TEST_DSN=postgresql://denali:denali-local@127.0.0.1:55450/denali \
  pytest -q tests/test_inventory_postgres.py
```

The fast suite skips rather than disguises the Postgres integration tests when
`DENALI_TEST_DSN` is absent. The independent web application is the next vertical
slice.

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
