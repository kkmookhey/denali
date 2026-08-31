# GCP code-to-cloud live acceptance — 2026-08-31

## Result

The GCP control-plane correlation slice passed end to end at confidence `1.0`:

1. Cloud Asset Inventory independently observed the live Cloud Run service.
2. Denali classified it as an AI workload from the explicit label and the
   `VERTEX_MODEL_ID` configuration **key**.
3. Denali stored the workload, runtime identity, and `HOSTED_ON` and `RUNS_AS` edges.
4. The source scanner found the exact Cloud Run declaration at immutable Git revision
   `b649f05fc09055dbc5ed724d3054a019efeefeae`.
5. Project number, location, and service name matched exactly.
6. Denali stored one `DEPLOYED_BY` edge, and the reporting query returned that deployment.

The acceptance used a disposable PostgreSQL database. It was deleted after the read-model
assertion passed, so the run could not reconcile or overwrite the persistent local tenant.

## Live fixture

| Field | Value |
| --- | --- |
| Project | `vertex-api-502308` |
| Project number | `32976044400` |
| Region | `us-central1` |
| Service | `denali-code-to-cloud` |
| Resource UID | `b17fe595-752d-4cef-bd0e-a1a0bd11f9da` |
| Accepted revision | `denali-code-to-cloud-00002-xfp` |
| Container image | `us-central1-docker.pkg.dev/vertex-api-502308/cloud-run-source-deploy/denali-code-to-cloud@sha256:88b2977bff2a8c707573cc3a9d0f11774b10cd029969f3f7ad06f5234f6d27cd` |
| Runtime identity | `denali-c2c-fixture@vertex-api-502308.iam.gserviceaccount.com` |
| Build identity | `denali-c2c-builder@vertex-api-502308.iam.gserviceaccount.com` |
| Source declaration | `examples/gcp-code-to-cloud/service.yaml:1` |
| Observed workload | `//run.googleapis.com/projects/vertex-api-502308/locations/us-central1/services/denali-code-to-cloud` |

The service is private, has `run.googleapis.com/maxScale=1`, and scales to zero when idle. Its
runtime identity has `roles/aiplatform.user`; its dedicated build identity has
`roles/run.builder`. No secret or credential is present in the source declaration. The
`/generate` route was not called during acceptance, so the test incurred no model invocation.

## Correlation evidence

Cloud Asset coverage was complete for all four supported planes: Cloud Run inventory and
relationships, and Cloud Functions Gen2 inventory and relationships. The run produced:

- three ingested assets: cloud resource, AI workload, and service-account identity;
- two runtime relationships: `HOSTED_ON` and `RUNS_AS`;
- one AI workload eligible for correlation;
- one ingested and reportable `DEPLOYED_BY` relationship; and
- exact match basis `literal_gcp_project_number`, `literal_gcp_location`, and
  `literal_cloud_run_service_name`.

The acceptance also found and fixed a provider-neutral read-model defect: the deployment
query required the legacy AWS-only `logical_id`. It now accepts `deployment_identifiers`, with
the legacy field retained solely for backward compatibility. A PostgreSQL regression proves
that GCP edges are returned by the same reporting contract as AWS edges.

## Runtime probe note

Cloud Run reported `Ready=True`, `ConfigurationsReady=True`, and `RoutesReady=True`. Both
revision rollouts logged a successful startup TCP probe and the application logged its
`listening` event on port 8080 with model `gemini-2.0-flash-001`.

An authenticated `/healthz` request from the validation workstation, including through the
official `cloud-run-proxy` component and with explicit service-level invoker bindings, was
answered by Google's front end with a generic 404. No `/healthz` request appeared in Cloud Run
request logs, so the response did not originate in the fixture container. This data-plane
routing issue is recorded separately and did not weaken the private access policy or the
independent control-plane correlation acceptance.

## Verification gates

- `pytest -q`: 181 passed, 19 expected PostgreSQL skips.
- `pytest -q tests/test_inventory_postgres.py` against a disposable database: 19 passed.
- `ruff check src tests`: passed.
- `node --check examples/gcp-code-to-cloud/server.mjs`: passed.
- `git diff --check`: passed.

## Exact teardown

The fixture is intentionally retained for repeatable acceptance. To remove it, run these
commands in order. Each target is fixture-specific; the shared Artifact Registry repository
is not deleted.

```bash
gcloud run services delete denali-code-to-cloud \
  --project vertex-api-502308 --region us-central1 --quiet

gcloud artifacts docker images delete \
  us-central1-docker.pkg.dev/vertex-api-502308/cloud-run-source-deploy/denali-code-to-cloud@sha256:88b2977bff2a8c707573cc3a9d0f11774b10cd029969f3f7ad06f5234f6d27cd \
  --delete-tags --quiet

gcloud projects remove-iam-policy-binding vertex-api-502308 \
  --member serviceAccount:denali-c2c-fixture@vertex-api-502308.iam.gserviceaccount.com \
  --role roles/aiplatform.user --condition=None --quiet

gcloud projects remove-iam-policy-binding vertex-api-502308 \
  --member serviceAccount:denali-c2c-builder@vertex-api-502308.iam.gserviceaccount.com \
  --role roles/run.builder --condition=None --quiet

gcloud iam service-accounts delete \
  denali-c2c-fixture@vertex-api-502308.iam.gserviceaccount.com \
  --project vertex-api-502308 --quiet

gcloud iam service-accounts delete \
  denali-c2c-builder@vertex-api-502308.iam.gserviceaccount.com \
  --project vertex-api-502308 --quiet
```

Cloud Build was enabled for this test but is project-global. Disable it only after confirming
that no other workload in `vertex-api-502308` uses it. The service-level invoker bindings are
deleted automatically with the service.
