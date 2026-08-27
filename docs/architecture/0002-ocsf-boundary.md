# ADR 0002: OCSF is an interchange format, not Denali's internal graph

**Status:** accepted — 2026-08-26

## Decision

Denali accepts and emits OCSF for findings and activity wherever an appropriate OCSF
class exists. Denali does not force durable inventory, source reconciliation, governance,
or permission relationships into an OCSF Detection Finding.

Every connector declares four independent capabilities:

| Capability | Meaning |
| --- | --- |
| Findings | Detection, compliance, vulnerability, or related findings |
| Inventory | Durable resources and lifecycle |
| Relationships | Hosting, identity, permission, code-to-cloud, or data edges |
| Activity | Runtime or control-plane events |

A connector may implement any subset. Missing capability is presented as missing
coverage, never as an empty result.

## Prowler reference integration

The first Prowler adapter is expected to use:

- JSON-OCSF for findings.
- The Prowler API for resources and scan context when the platform is installed.
- An optional graph provider for Prowler's tenant Neo4j database.
- A thin Prowler check plugin only when a customer wants Denali findings visible inside
  Prowler.

No Prowler source fork or UI patch is required.

## Why

An OCSF finding says that a producer observed a security condition. A Wiz-style attack
path additionally requires durable resource identities, execution principals, effective
permissions, topology, lifecycle, and collection coverage. Treating findings as that
graph would fabricate relationships or make missing relationships look safe.

