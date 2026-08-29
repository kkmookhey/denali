# Runtime accuracy audit — 2026-08-27

This audit compares Denali's stored and displayed runtime observations with fresh reads from the underlying provider APIs. It is an accuracy checkpoint, not a claim that every possible telemetry plane is covered.

## Verified output

### AWS Bedrock

- Source: AWS CloudTrail Event History, account `331145994818`, region `ap-south-1`.
- Profile used for the read-only verification: `sara-sales`.
- Audited window: `2026-08-27T01:27:47Z` through `2026-08-27T17:50:22Z`.
- Fresh provider read: 41 records and 41 unique CloudTrail event IDs.
- Denali storage: the same 41 event IDs, with no missing or extra live records.
- Outcome: all 41 records were successful model-invocation observations.
- Actor and model identifiers can be reproduced from the retained, privacy-safe evidence payload.

This proves reconciliation for the bounded CloudTrail management-event window. It does not prove collection of prompts, responses, application traces, data events, or host-level behavior.

### Microsoft Entra

- Source: Microsoft Graph for corporate tenant `5519d103-66f6-4b0d-979f-35c233b454ed`.
- Audited window: the preceding 30 days at collection time.
- Fresh provider read: 1,427 service principals, of which 51 matched the current AI application catalog.
- Runtime observations: 22 catalog-matched sign-ins and 5 directory audit changes whose target resource exactly matched an AI service-principal object ID.
- Outcomes: 20 successful and 7 failed observations.
- Denali storage: 27 live Entra activity records after rebuilding the local derived cache from the fresh read.
- Every stored actor is reproducible from a retained, privacy-safe source identity field.

All 51 AI application matches currently use a display-name alias. They are reviewable inventory classifications, not exact application-ID identifications and not security findings. Sign-ins prove observed use, not application ownership. Directory changes are associated only by exact target object ID.

### Product totals

The default runtime API and UI now exclude transparent fixture observations:

- 68 live retained observations.
- 41 live observations in the last 24 hours at audit time.
- 2 live telemetry providers: AWS Bedrock and Microsoft Entra.
- 7 failed observations, all outcomes rather than security findings.
- 6 transparent demo observations available only through an explicit opt-in.

The six demo observations retain `attributes.fixture = true`. Repository and API queries exclude them by default; the UI exposes a labeled include/hide control. Integration-test observations use separate tenant IDs and cannot appear in the product tenant.

## Defects corrected during the audit

1. Entra directory audit changes previously fell back to display-name matching when the target object ID did not match. This could assign an unrelated change to an AI application. Audit association is now exact-ID only.
2. Entra sign-ins without a status code were previously normalized as successful. Missing status is now `unknown`; only error code zero is successful.
3. Entra evidence did not retain the source identity fields used to normalize the actor. Privacy-safe actor fields are now retained so the claim can be reproduced.
4. AWS activity evidence retained too little source metadata for independent reconciliation. It now retains safe event, identity, request-identifier, account, region, and error metadata while excluding prompts, messages, and responses.
5. Runtime totals combined live and transparent demo records. Live-only is now the default at the repository, API, and UI layers.

## Known limits and next checks

- Live GCP Vertex AI and Google Workspace runtime collection remains unverified while Google authentication is parked. Existing Google rows are transparent fixtures.
- Entra AI catalog matching needs a curated exact application-ID catalog before it can be described as exact identification.
- AWS coverage is currently CloudTrail management-plane activity. Bedrock invocation logging, application traces, and optional workload telemetry are separate future planes.
- eBPF is not required for the current provider-runtime milestone. It should be considered later for self-hosted models, MCP servers, local agent processes, and network/process behavior that provider audit logs cannot answer.
- Runtime observations remain separate from detections and issues. A failed call or an AI application sign-in is not itself a security verdict.

## Runtime detection audit

The first deterministic detection evaluation was run against the retained live Entra
observations after the activity and inventory reconciliation above. It produced two
open detections, and a second evaluation retained the same detection identities rather
than creating duplicates.

### High — consent changed for unreviewed Claude for Office

- Two distinct Microsoft directory-audit record IDs were retained.
- Both records identify
  `naveenkumar.venkadachalam@networkintelligence.ai` as the initiating user and share
  Microsoft correlation ID `c2b6644b-53a7-4b5c-ba0b-d1160a592512`.
- The records occurred 420 milliseconds apart and describe `Add delegated permission
  grant` and `Consent to application`; Denali correctly groups them as one consent
  operation rather than two detections.
- The target service-principal object ID exactly matches the independently collected
  `Claude for Office` AI application.
- The active application assertion reports delegated scopes `Calendars.Read`,
  `Mail.ReadWrite`, `User.Read`, `offline_access`, `openid`, and `profile`.
  `Mail.ReadWrite` is the explicit reason severity is high.
- The application governance state is `unreviewed`. The detection does not claim that
  the permission was exercised or abused.

### Medium — repeated failed access to Fireflies.ai

- Three distinct Microsoft sign-in record IDs were retained for the same exact user
  and exact AI application inside 12 hours 33 minutes.
- All three records identify
  `raghavendra.deshpande@networkintelligence.ai`, target `Fireflies.ai`, and report
  Entra error 50074: `Strong Authentication is required.`
- The application ID exactly matches an independently collected, externally verified
  `ai_application` asset.
- The three records share one Microsoft trace identifier. Denali therefore describes
  the observable fact—three failed sign-in records—and does not claim three independent
  password attempts, malicious intent, or compromise.

### Coverage result

- The consent rule evaluation is complete: the required AI application inventory and
  directory-audit planes are complete.
- The failed-sign-in rule evaluation is partial at the product-tenant level. The
  corporate Entra connection used by the confirmed detection has complete inventory
  and sign-in collection, but another configured Entra connection has a failed or
  partial sign-in plane. Denali retains the confirmed evidence while refusing to call
  the overall rule evaluation clean.

## Regression gate

- Python suite: 135 passed, 13 skipped.
- PostgreSQL integration suite: 13 passed.
- Runtime detection API and pure-rule suite: 15 passed.
- Ruff formatting and lint: passed.
- Production web build: passed.
