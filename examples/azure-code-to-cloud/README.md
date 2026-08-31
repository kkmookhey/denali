# Azure code-to-cloud acceptance fixture

This deliberately small Azure Container App proves Denali's exact source-to-runtime identity
join on Azure. It uses Consumption scaling with zero minimum replicas and one maximum replica,
a system-assigned managed identity, and the `denali_ai_workload=true` tag.

- `GET /healthz` verifies the container without calling a model.
- `POST /generate` can call an Azure OpenAI deployment with managed identity when
  `AZURE_OPENAI_ENDPOINT` is supplied.
- `container-app.resource.json` is an exact Azure resource export captured after deployment.

The live acceptance record and teardown state are documented in
`docs/product/azure-code-to-cloud-live-acceptance-2026-08-31.md`.
