# Denali pilot launch checklist

Use this as the ordered launch-control artifact. Do not skip ahead: the production URL is an
input to Clerk and provider callbacks, and the Modal URL is an input to Vercel.

## Current checkpoint — 2026-09-01

- [x] Hosted multi-tenant application code is implemented and committed.
- [x] The configured Clerk development publishable key resolves to a live Clerk JWKS endpoint.
- [ ] Select the permanent production URL. `https://denali.example.com` is still a placeholder.
- [ ] Add the Clerk backend key material and finish the production Clerk configuration.
- [ ] Provision Neon and create separate runtime and migration connection strings.
- [ ] Create the `denali-production` Modal secret.
- [ ] Run migrations and deploy the Modal API/worker application.
- [ ] Create and deploy the Vercel project. Vercel has not been deployed yet.
- [ ] Complete two-organization Clerk acceptance.
- [ ] Configure and accept AWS, Azure, GCP, and GitHub individually.

## Ordered TODOs

### 1. Choose the production URL and regions

- [ ] Choose the final web URL, for example `https://denali.company.com`.
- [ ] Choose a Neon region and a compatible nearby Modal region.
- [ ] Reserve the custom domain, or create the Vercel project name now so its stable
  `<project>.vercel.app` URL is known.

Record these non-secret values:

```text
DENALI_WEB_URL=https://<production-domain>
DENALI_CORS_ORIGINS=https://<production-domain>
CLERK_AUTHORIZED_PARTIES=https://<production-domain>
DENALI_MODAL_REGION=<modal-region>
```

### 2. Finish Clerk

- [ ] Use a Clerk production instance for the real pilot (`pk_live_...` / `sk_live_...`). The
  currently configured key is a development `pk_test_...` key.
- [ ] Enable Organizations and require organization membership.
- [ ] Keep `org:admin` and `org:member`; disable personal-account access.
- [ ] Restrict signup to invitations.
- [ ] Create the approved pilot organizations and invite users.
- [ ] Add the final production origin and redirect URLs in Clerk.
- [ ] Copy the Secret Key and the PEM JWT public key from Clerk Dashboard → API Keys.

Destinations:

| Variable | Destination | Classification | Required |
| --- | --- | --- | --- |
| `VITE_CLERK_PUBLISHABLE_KEY` | Vercel | Public client configuration | Yes |
| `CLERK_SECRET_KEY` | Modal secret | Secret | Yes |
| `CLERK_JWT_KEY` | Modal secret | Public cryptographic key, backend-only | Yes |
| `CLERK_AUTHORIZED_PARTIES` | Modal secret/config | Non-secret origin allowlist | Yes |
| `DENALI_CLERK_ORGANIZATIONS` | Modal secret/config | Non-secret Clerk organization ID allowlist | Recommended for the pilot |

Never add `CLERK_SECRET_KEY` to Vercel or any `VITE_...` variable.

### 3. Provision Neon

- [ ] Create a PostgreSQL project in the selected region.
- [ ] Create a least-privilege runtime role and a migration/owner role.
- [ ] Obtain the pooled PgBouncer runtime URL and direct migration URL with TLS required.
- [ ] Store both only in Modal, never in Vercel.
- [ ] Enable backups and record a restore-test procedure.

| Variable | Value | Destination | Classification |
| --- | --- | --- | --- |
| `DENALI_DSN` | Neon pooled runtime URL | Modal secret | Secret |
| `DENALI_MIGRATION_DSN` | Neon direct migration URL | Modal secret | High-privilege secret |

### 4. Create the core Modal secret

Create an ignored local file named `.env.modal.production`. It must contain only the core
backend values at this stage:

```dotenv
DENALI_DSN=
DENALI_MIGRATION_DSN=
DENALI_WEB_URL=https://<production-domain>
DENALI_CORS_ORIGINS=https://<production-domain>
CLERK_SECRET_KEY=
CLERK_JWT_KEY=
CLERK_AUTHORIZED_PARTIES=https://<production-domain>
DENALI_CLERK_ORGANIZATIONS=
```

Then create or replace the named Modal secret without placing values in shell history:

```bash
modal secret create --from-dotenv .env.modal.production denali-production
```

- [ ] Confirm `modal secret list` includes `denali-production`.
- [ ] Keep `.env.modal.production` local and ignored; do not commit or send it in chat.

### 5. Migrate and deploy Modal

`DENALI_MODAL_REGION` is a deploy-shell variable, not a value loaded from the runtime secret.

```bash
export DENALI_MODAL_REGION=<modal-region>
modal run modal_app.py::migrate_database
modal deploy modal_app.py
```

- [ ] Record the deployed Modal `api` HTTPS origin.
- [ ] Verify `<modal-origin>/healthz` returns `{"status":"ok"}`.
- [ ] Enable Modal failure and timeout alerts.

### 6. Create and deploy Vercel

Create a Vercel project from this repository with `web` as the Root Directory. Vercel needs
only these two values:

| Variable | Value | Classification |
| --- | --- | --- |
| `VITE_CLERK_PUBLISHABLE_KEY` | Clerk publishable key | Public client configuration |
| `MODAL_API_ORIGIN` | Deployed Modal origin, without trailing slash | Public server configuration |

- [ ] Add both values for Production and Preview as appropriate.
- [ ] Deploy the project and attach the chosen domain.
- [ ] Verify `/`, an authenticated refresh, SPA navigation, and `/api/healthz`.
- [ ] Confirm no Clerk, Neon, Modal, or provider secret exists in Vercel.

### 7. Reconcile the final URL

If the deployed URL differs from step 1, update all of these together and redeploy:

- [ ] `DENALI_WEB_URL`
- [ ] `DENALI_CORS_ORIGINS`
- [ ] `CLERK_AUTHORIZED_PARTIES`
- [ ] Clerk allowed origins and redirect URLs
- [ ] `DENALI_AZURE_CONSENT_REDIRECT_URI`
- [ ] `DENALI_GITHUB_CALLBACK_URL`

### 8. Accept Clerk tenancy before adding providers

- [ ] Sign in through the hosted UI.
- [ ] Verify users without an active organization cannot load Denali.
- [ ] Verify `org:member` can read and receives `403` for mutations.
- [ ] Verify `org:admin` can mutate governance and connections.
- [ ] Switch between two organizations and confirm `/api/v1/context` returns different Denali
  tenant UUIDs and no data crosses organizations.

### 9. Add providers one at a time

Add each provider's variables to `.env.modal.production`, replace the Modal secret with
`--force`, redeploy Modal, and complete its hosted acceptance before starting the next provider.

#### AWS

```text
DENALI_MODAL_AWS_ROLE_ARN
DENALI_AWS_ONBOARDING_BUCKET
DENALI_AWS_PRINCIPAL_ARN
```

- `DENALI_MODAL_AWS_ROLE_ARN` and the bucket/principal identifiers are non-secret configuration.
- Configure AWS to trust Modal OIDC and scope the role to the exact Modal workspace, environment,
  app, and functions. Do not add long-lived AWS access keys.

#### Azure

```text
DENALI_AZURE_ONBOARDING_BUCKET
DENALI_AZURE_CLIENT_ID
DENALI_AZURE_CLIENT_SECRET
DENALI_AZURE_CONSENT_REDIRECT_URI=https://<production-domain>
```

- `DENALI_AZURE_CLIENT_SECRET` is the secret; the other entries are identifiers/configuration.
- Register the final redirect URL before browser acceptance.

#### Google Cloud

```text
DENALI_GCP_ONBOARDING_BUCKET
DENALI_GCP_OPERATOR_PROJECT_ID
```

- These are non-secret identifiers.
- Configure keyless runtime credentials for Google Application Default Credentials. Do not commit
  a service-account JSON key. GCP acceptance is blocked until Modal can obtain that identity.

#### GitHub

```text
DENALI_GITHUB_APP_ID
DENALI_GITHUB_CLIENT_ID
DENALI_GITHUB_CLIENT_SECRET
DENALI_GITHUB_APP_SLUG
DENALI_GITHUB_PRIVATE_KEY
DENALI_GITHUB_CALLBACK_URL=https://<production-domain>/api/v1/connections/github/oauth/callback
```

- `DENALI_GITHUB_CLIENT_SECRET` and `DENALI_GITHUB_PRIVATE_KEY` are secrets.
- Store the PEM private key directly in Modal; do not add it to Vercel or the repository.
- Configure GitHub's setup callback as
  `https://<production-domain>/api/v1/connections/github/setup/callback`.

### 10. Launch gate

- [ ] Run one complete onboarding, validation, disable, and delete flow for each enabled provider.
- [ ] Confirm validation survives API-container replacement and duplicate requests return
  `already_running`.
- [ ] Enable Vercel deployment monitoring, Modal alerts, and Neon database alerts/backups.
- [ ] Review logs for tenant/job/connection IDs and verify tokens and secrets never appear.
- [ ] Record the deployed URLs, resource owners, rollback procedure, and acceptance date.

## Secret summary

Actual secrets that must be stored in Modal are:

```text
CLERK_SECRET_KEY
DENALI_DSN
DENALI_MIGRATION_DSN
DENALI_AZURE_CLIENT_SECRET                 # when Azure is enabled
DENALI_GITHUB_CLIENT_SECRET                # when GitHub is enabled
DENALI_GITHUB_PRIVATE_KEY                  # when GitHub is enabled
```

`CLERK_JWT_KEY` is public key material but remains backend-only. Vercel receives no private
secret: only `VITE_CLERK_PUBLISHABLE_KEY` and `MODAL_API_ORIGIN`.
