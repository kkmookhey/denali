import type {
  Asset,
  AssetDetail,
  Coverage,
  CodeToCloudDeployment,
  Finding,
  FindingDetail,
  FindingSummary,
  Issue,
  IssueDetail,
  IssueEvaluation,
  IssueSummary,
  RuntimeActivity,
  RuntimeActivityDetail,
  RuntimeActivitySummary,
  RuntimeDetection,
  RuntimeDetectionDetail,
  RuntimeDetectionEvaluation,
  RuntimeDetectionSummary,
  Summary,
  Vulnerability,
  VulnerabilityDetail,
  VulnerabilitySummary,
} from "./types";

const API_BASE = "/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  summary: () => request<Summary>("/v1/inventory/summary"),
  assets: () => request<{ items: Asset[] }>("/v1/inventory/assets?limit=500"),
  asset: (id: string) => request<AssetDetail>(`/v1/inventory/assets/${id}`),
  coverage: () => request<{ items: Coverage[] }>("/v1/sources/coverage"),
  findingSummary: () => request<FindingSummary>("/v1/findings/summary"),
  findings: () => request<{ items: Finding[] }>("/v1/findings?limit=500"),
  finding: (id: string) => request<FindingDetail>(`/v1/findings/${id}`),
  vulnerabilitySummary: () => request<VulnerabilitySummary>("/v1/vulnerabilities/summary"),
  vulnerabilities: () => request<{ items: Vulnerability[] }>("/v1/vulnerabilities?limit=500"),
  vulnerability: (id: string) =>
    request<VulnerabilityDetail>(`/v1/vulnerabilities/${id}`),
  issueSummary: () => request<IssueSummary>("/v1/issues/summary"),
  issues: () => request<{ items: Issue[] }>("/v1/issues?limit=500"),
  issue: (id: string) => request<IssueDetail>(`/v1/issues/${id}`),
  issueEvaluations: () => request<{ items: IssueEvaluation[] }>("/v1/issues/evaluations"),
  codeToCloudDeployments: () =>
    request<{ items: CodeToCloudDeployment[] }>("/v1/code-to-cloud/deployments"),
  activitySummary: (includeFixtures = false) =>
    request<RuntimeActivitySummary>(
      `/v1/activity/summary?include_fixtures=${includeFixtures}`,
    ),
  activity: (includeFixtures = false) =>
    request<{ items: RuntimeActivity[] }>(
      `/v1/activity?limit=500&include_fixtures=${includeFixtures}`,
    ),
  activityForAsset: (assetId: string) =>
    request<{ items: RuntimeActivity[] }>(
      `/v1/activity?asset_id=${encodeURIComponent(assetId)}&limit=500`,
    ),
  activityDetail: (id: string) =>
    request<RuntimeActivityDetail>(`/v1/activity/${id}`),
  detectionSummary: () => request<RuntimeDetectionSummary>("/v1/detections/summary"),
  detections: () => request<{ items: RuntimeDetection[] }>("/v1/detections?limit=500"),
  detectionEvaluations: () =>
    request<{ items: RuntimeDetectionEvaluation[] }>("/v1/detections/evaluations"),
  detection: (id: string) =>
    request<RuntimeDetectionDetail>(`/v1/detections/${id}`),
  governance: (
    id: string,
    update: { status: Asset["governance_status"]; owner?: string | null; notes?: string | null },
  ) =>
    request<{ id: string; governance_status: string; owner: string | null; notes: string | null }>(
      `/v1/inventory/assets/${id}/governance`,
      { method: "PATCH", body: JSON.stringify(update) },
    ),
};
