# GitHub validation-density checkpoint — 2026-08-31

## Scope completed

The large-installation GitHub validation UI is implemented and automatically verified.
The previous flat set of 54 equally prominent cards is replaced by a repository-level
presentation that keeps the accepted evidence contract intact:

- An aggregate summary reports exact repository count, independent plane-check count,
  passed checks, and failed or unknown checks.
- Results are grouped by exact repository and retain both the immutable numeric repository
  ID and GitHub node ID.
- Each repository summary retains the independent Metadata, Contents/default revision, and
  Actions workflow-inventory states.
- Repositories with failures, unknowns, or missing declared results sort first and expand by
  default. Fully passing repositories remain collapsed until inspected.
- Filters expose needs-attention, all, and passing repositories. A new validation resets the
  default to needs-attention; when no attention result exists, all repositories are shown.
- A declared plane without a recorded result is rendered as unknown. A validation result
  that does not match the recorded exact repository boundary is rendered as an expanded,
  unbound attention group. Neither condition silently disappears.

The implementation is in `web/src/App.tsx` and `web/src/styles.css`.

## Verification performed

- Full fast suite: `159 passed, 18 skipped`.
- Focused GitHub suite: `4 passed`.
- Ruff: all checks passed.
- `uv lock --check`: passed.
- Production web build: passed with Vite.
- Review Docker image build: passed.
- `docker compose config --quiet`: passed without printing values.
- `git diff --check`: passed.
- Isolated review runtime health: passed through
  `http://127.0.0.1:3081/api/healthz` before that temporary runtime was removed.
- Live persisted dataset through the review proxy: 18 exact repositories, 54 results, and
  54 passed results.

One non-blocking Starlette `TestClient`/httpx deprecation warning remains.

## Credential cleanup state

The legacy `GOOGLE_OAUTH_CLIENT_SECRET` entry that was exposed in the prior session has been
removed from the ignored local `.env`. The file remains mode `0600`, contains no malformed
dotenv keys, and Compose parses it successfully. The non-secret `GOOGLE_OAUTH_CLIENT_ID`
entry remains temporarily so the exact remote OAuth client can be identified. Neither Google
OAuth variable is referenced anywhere in Denali.

Remote deletion or rotation is still required in Google Cloud. Removing the local secret did
not revoke the provider-side credential. After deleting the exact OAuth client identified by
the retained client ID, remove the unused `GOOGLE_OAUTH_CLIENT_ID` line from `.env` and rerun
`docker compose config --quiet` without printing values.

The GitHub App client secret and PEM were not exposed or changed.

## Browser diagnosis and restart boundary

The supported in-app browser flow was initialized for the Google Cloud credentials page, but
browser selection returned `No browser is available`. The supported browser inventory was
then checked once and returned an empty list. No alternate browser-control mechanism was used.

The human is ending this session to repair browser attachment. After the browser is fixed,
the next session should:

1. Read this checkpoint first.
2. Confirm the browser inventory is non-empty and open the Google Cloud credentials page.
3. Match the exact OAuth client to the retained local `GOOGLE_OAUTH_CLIENT_ID`, delete or
   rotate it in Google Cloud, remove the remaining local client-ID entry, and validate
   Compose without printing values.
4. Build and launch the changed web image on an isolated review port connected to
   `denali_default`; do not replace the accepted port-3080 container yet.
5. Visually accept the GitHub connection against the live 18-repository/54-plane record:
   confirm the four aggregate values, the default All filter for a fully passing run, 18
   collapsed repository rows, exact numeric and node IDs, the three per-plane chips and
   expandable details, and the Needs attention/All/Passing filters.
6. Exercise or fixture a failed/unknown and missing/unbound presentation before declaring
   the failure-first behavior accepted.
7. After acceptance, replace the port-3080 web container deliberately while retaining the
   stopped pre-polling rollback container until the new UI is accepted.

## Preserved local runtime

- `denali-api-github-e2e` serves port `8088` on `denali_default` with network alias `api`.
- `denali-web-github-live` serves the previously accepted UI on port `3080`.
- `denali-web-github-prepoll` remains stopped for rollback.
- The PostgreSQL container and previously stopped API rollback containers are unchanged.
- The temporary `denali-web-density-review` container and its review-only image are removed
  during session cleanup; the next session should rebuild from the committed source.

## Deferred work retained

- Increase typography on the newer product pages.
- Add application browser-history routing so Back navigates within Denali.
- Improve elapsed-time and retry visibility during cloud IAM propagation waits.
- Add GitHub branch-protection posture only as a separate explicitly permissioned plane.
- Add repository source collection and exact code-to-cloud correlation after onboarding.
- Start Slack or Jira onboarding only after the current product-quality work is accepted.
