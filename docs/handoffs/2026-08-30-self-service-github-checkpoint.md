# Self-service GitHub connection checkpoint — 2026-08-30

## Scope completed

The bounded GitHub onboarding slice is implemented and locally verified. It does not add
Slack, Jira, GitHub Enterprise Server, webhooks, repository administration, branch-protection
posture, source collection, or remediation.

The connection flow uses a Denali-owned GitHub App with Metadata read, Contents read, and
Actions read. Customers use GitHub's native installation repository picker. Denali distrusts
the Setup URL's bare `installation_id`, performs an explicit state- and PKCE-protected user
authorization step, verifies the signed-in user can access that exact App installation, binds
each selected repository by immutable numeric ID and node ID, and discards the user token and
PKCE verifier.

Runtime validation creates a separate short-lived installation token for one exact recorded
repository at a time. Repository identity is rebound before three independent planes are
tested: metadata, the default Git ref through Contents read, and Actions workflow inventory.
An `all` installation never silently expands Denali coverage; new repositories require an
explicit reconfiguration and verified boundary update.

The accepted security and evidence contract is in
`docs/architecture/0021-self-service-github-connections.md`.

## Verification performed

- Full fast suite: `159 passed, 18 skipped`.
- Explicit PostgreSQL contract suite: `18 passed`.
- Focused GitHub suite: `4 passed`.
- Ruff: all checks passed.
- `uv lock --check`: passed.
- Production web build: passed with Vite.
- API Docker image build: passed with the GitHub extra and PyJWT crypto support.
- Web Docker image build: passed.
- `git diff --check`: passed.
- Live local API and web health checks: passed through `http://127.0.0.1:3080/api/healthz`.
- Live GitHub customer simulation: passed for the `kkmookhey` installation.
- Exact repository binding: 18 repository IDs and node IDs recorded; the installation's
  `all` selection was resolved to this explicit snapshot and does not silently expand scope.
- Live evidence planes: 54 of 54 passed — Metadata, Contents/default revision, and Actions
  workflow inventory for each of the 18 exact repositories.
- OAuth evidence boundary: the installation was rebound to the signed-in GitHub user, and
  the temporary user token and PKCE verifier were discarded after setup.
- Callback progress UX: fixed a stale loading state found during acceptance. The web app now
  polls connection state every two seconds while any background validation is running and
  automatically renders the completed result.

The local `.env` initially contained two legacy Google OAuth labels in a space-delimited form
that Docker Compose could not parse. Their labels were normalized to valid ignored dotenv keys
without changing their values. This local file is not part of the GitHub connection record.

One non-blocking Starlette `TestClient`/httpx deprecation warning remains.

## Live local runtime

- `denali-api-github-e2e` serves port `8088` on `denali_default` with network alias `api`.
  It preserves the previous read-only AWS profile mount and Google ADC mount.
- The ignored, mode-`0600` GitHub App PEM is mounted read-only at
  `/run/secrets/denali-github-app.pem`; the ignored, mode-`0600` local `.env` supplies the
  client secret. Neither credential is stored in the database or image.
- `denali-web-github-live` serves port `3080` on `denali_default`.
- The pre-polling web container is stopped as `denali-web-github-prepoll` for rollback.
- Prior API containers `denali-api-github-live`, `denali-api-gcp-live`, and `denali-api-1`
  remain stopped for rollback; they were not deleted.
- GitHub App registration evidence and the local operator configuration are recorded in
  `docs/deployment/github-app.md`. PR #1 was reviewed and merged after removing the recorded
  client-secret suffix and clarifying how the PEM and OAuth client secret are used.

The in-app browser runtime had no attached browser, so the authenticated GitHub screens were
operated by the human tester. Denali's persisted result and all 54 read-only validation calls
were then independently checked through the local API.

## Human acceptance completed

The organization-owned `transilience-denali` GitHub App was registered under
`transilienceai` with:

- Homepage URL: `http://127.0.0.1:3080`
- Setup URL: `http://127.0.0.1:8088/v1/connections/github/setup/callback`
- OAuth callback URL: `http://127.0.0.1:8088/v1/connections/github/oauth/callback`
- Repository permissions: Metadata read, Contents read, Actions read
- Webhooks inactive and no subscribed events
- Installable by any account intended to self-onboard
- “Request user authorization (OAuth) during installation” disabled; Denali performs the
  explicit verification flow after the setup return

The local API was configured without printing either credential. The private key fingerprint
matched the registration evidence. The human customer simulation installed the App, completed
the explicit OAuth ownership check, returned to Denali, and produced a healthy connection for
18 exact repositories. The provider and evidence contract is accepted. One final visual UX
check remains after the stale-spinner fix: hard-refresh Connections and confirm the completed
validation grid replaces the progress state without another manual refresh. Hosted deployment
also requires replacing the localhost Homepage, Setup, and OAuth callback URLs and loading both
credentials from the production secret manager.

## Deferred work retained

- Increase typography on the newer product pages.
- Add application browser-history routing so Back navigates within Denali.
- Improve elapsed-time and retry visibility during cloud IAM propagation waits.
- Add GitHub branch-protection posture only as a separate explicitly permissioned plane.
- Add repository source collection and code-to-cloud correlation after onboarding acceptance.
- Start Slack or Jira onboarding only after this GitHub slice is accepted.
