# Azure code-to-cloud live acceptance — 2026-08-31

## Result

The Azure control-plane correlation slice passed end to end at confidence `1.0`:

1. Azure Resource Graph independently observed the live Container App.
2. Denali classified it as an AI workload from the explicit tag and the
   `AZURE_OPENAI_DEPLOYMENT_ID` configuration **key**.
3. Denali stored the workload, cloud resource, system-assigned managed identity, and
   `HOSTED_ON` and `RUNS_AS` edges.
4. The source scanner found the exact Azure resource export at immutable Git revision
   `e14214e82d7077850732860d5862b8fa99caf300`.
5. Subscription ID, resource group, location, and Container App name matched exactly.
6. Denali stored one `DEPLOYED_BY` edge, and the reporting query returned that deployment.

The acceptance used a disposable PostgreSQL database. It was deleted after the read-model
assertion passed, so the run could not reconcile or overwrite the persistent local tenant.

## Live fixture

| Field | Value |
| --- | --- |
| Subscription | `Azure CIS Agent Testing` (`8cd2b4cc-c789-466d-a8f7-8f51fb20985d`) |
| Region | `centralindia` |
| Resource group | `denali-c2c-azure-20260831` |
| Container App | `denali-code-to-cloud` |
| Accepted revision | `denali-code-to-cloud--acceptance` |
| Container image | `denalic2c8cd2b4cc.azurecr.io/denali-code-to-cloud@sha256:32958925f96ff55124d3fefbc4d18f2fd1d2b5fa131ce237f9dbaeff0438743d` |
| Runtime identity | system-assigned principal `51684963-8eec-4a80-8421-cf41a99a179c` |
| Source declaration | `examples/azure-code-to-cloud/container-app.resource.json:1` |
| Observed workload | `/subscriptions/8cd2b4cc-c789-466d-a8f7-8f51fb20985d/resourcegroups/denali-c2c-azure-20260831/providers/microsoft.app/containerapps/denali-code-to-cloud` |

The Container App used internal ingress, Consumption scaling with zero minimum replicas and
one maximum replica, and an image pinned by digest. Its health route did not call a model.
`AZURE_OPENAI_ENDPOINT` was intentionally absent and `/generate` was not invoked, so the
acceptance made no Azure OpenAI request.

## Correlation evidence

Resource Graph coverage was complete for all four supported planes: Container Apps inventory
and relationships, and Function Apps inventory and relationships. The subscription-wide run
observed the six pre-existing Container Apps without modifying them and the dedicated fixture.
It produced:

- nine ingested assets across the full subscription snapshot;
- one AI workload eligible for correlation;
- two runtime relationships, `HOSTED_ON` and `RUNS_AS`;
- one ingested and reportable `DEPLOYED_BY` relationship; and
- exact match basis `literal_azure_subscription_id`,
  `literal_azure_resource_group`, `literal_azure_location`, and
  `literal_azure_container_app_name`.

No environment value or secret was stored by the collector. The live harness used the Azure
CLI only as an authenticated transport adapter into the production `AzureDeploymentConnector`;
parsing, normalization, persistence, correlation, and reporting all ran through production
Denali code.

## Connected-browser acceptance

Azure Portal was opened with the authenticated subscription account and showed the exact
Container App as `Running`, in `Central India`, under the dedicated resource group and expected
subscription. The overview visibly showed the internal application URL and
`denali_ai_workload=true` and `denali_test=true` tags.

The freshly built Denali web application was also inspected in the browser. The existing Azure
connection visibly rendered step 4, **Collect deployment identities**, with the Resource Graph,
revision, image, managed-identity, and no-app-setting-values explanation. Because that
connection predates the scope, the corrected final UI disables collection and explains that a
new plan must explicitly adopt it; the API also rejects a missing scope before starting a job.
The new-connection form visibly rendered checked **Code-to-cloud deployments** scope text for
Container Apps and Function Apps. The Code to cloud reporting route rendered without
navigation or layout errors. No onboarding form or collection action was submitted during
visual acceptance.

## Verification gates

- `pytest -q`: 190 passed, 19 expected PostgreSQL skips.
- `pytest -q tests/test_inventory_postgres.py` against a disposable database: 19 passed.
- `ruff check src tests`: passed.
- `npm run build` in `web`: passed.
- `node --check examples/azure-code-to-cloud/server.mjs`: passed.
- `git diff --check`: passed.

## Exact teardown

Deletion of the dedicated resource group `denali-c2c-azure-20260831` was accepted after live
and browser acceptance. Azure activity records show successful deletion of the fixture
Container App, Basic Container Registry, and fixture-scoped role assignment. Direct reads of
the Container App, managed environment, and registry each returned `ResourceNotFound`, so the
app, pinned image, environment, managed identity, and role assignment no longer remain or
incur fixture cost. The six pre-existing Container Apps in other resource groups were not
changed.

Azure Resource Manager still reported the now-empty resource-group shell as `Deleting` at
`2026-08-31T21:05:50Z`, more than 20 minutes after accepting the request. This is provider-side
asynchronous cleanup, not a retained fixture. The exact non-mutating follow-up check is:

```bash
az group exists --name denali-c2c-azure-20260831 -o tsv
```
