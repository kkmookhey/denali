# GCP code-to-cloud acceptance fixture

This deliberately small Cloud Run service proves Denali's source-to-runtime identity join on GCP. It is private, scales to zero, is capped at one instance, and is tagged with `denali_ai_workload=true` so the collector can classify it without reading environment-variable values.

- `GET /healthz` verifies the container without calling a model.
- `POST /generate` calls Vertex AI with the attached service account and a bounded response size.
- `service.yaml` is generated from the live Cloud Run service and committed after deployment. It supplies the exact project, region, and service-name identity that Denali correlates.

The live acceptance record and exact teardown commands are in `docs/product/gcp-code-to-cloud-live-acceptance-2026-08-31.md`.
