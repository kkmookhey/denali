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

The direct `docker compose build` wrapper remains blocked by a pre-existing malformed `.env`
file. Its contents were not read, printed, or rewritten. The exact Dockerfiles were built
directly instead.

One non-blocking Starlette `TestClient`/httpx deprecation warning remains.

## Live local runtime

- `denali-api-github-live` serves port `8088` on `denali_default` with network alias `api`.
  It preserves the previous read-only AWS profile mount and Google ADC mount.
- `denali-web-github-live` serves port `3080` on `denali_default`.
- Prior containers `denali-api-gcp-live`, `denali-api-1`, and `denali-web-1` are stopped and
  retained for immediate rollback; they were not deleted.
- The API currently has no GitHub App configuration, so the UI correctly reports GitHub setup
  as unavailable until the operator registration below is completed.

The in-app browser runtime had no attached browser, so authenticated visual interaction could
not be automated. Human visual and end-to-end GitHub acceptance remain required.

## Human operator step required

Create an organization-owned GitHub App under `transilienceai` with:

- Homepage URL: `https://github.com/transilienceai/denali`
- Setup URL: `http://127.0.0.1:8088/v1/connections/github/setup/callback`
- OAuth callback URL: `http://127.0.0.1:8088/v1/connections/github/oauth/callback`
- Repository permissions: Metadata read, Contents read, Actions read
- Webhooks inactive and no subscribed events
- Installable by any account intended to self-onboard
- “Request user authorization (OAuth) during installation” disabled; Denali performs the
  explicit verification flow after the setup return

Generate one client secret and one PEM private key. Do not paste either into chat, commit it,
or store it in the connection database. The API needs the App ID, client ID, client secret,
slug, callback URL, and the path of a read-only mounted PEM. Recreate the current API container
with those operator settings while retaining the AWS and Google mounts.

Then perform the human customer simulation:

1. Refresh Connections and add a GitHub connection plan.
2. Select **Install / configure GitHub App**.
3. Review the three read permissions in GitHub and select one or more repositories.
4. Complete the brief installer-verification return.
5. Confirm Denali names the exact repositories, the temporary user token is not exposed, and
   every repository/plane validation result is visible independently.

## Deferred work retained

- Increase typography on the newer product pages.
- Add application browser-history routing so Back navigates within Denali.
- Improve elapsed-time and retry visibility during cloud IAM propagation waits.
- Add GitHub branch-protection posture only as a separate explicitly permissioned plane.
- Add repository source collection and code-to-cloud correlation after onboarding acceptance.
- Start Slack or Jira onboarding only after this GitHub slice is accepted.
