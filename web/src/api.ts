import type {
  Asset,
  AssetDetail,
  Coverage,
  Finding,
  FindingDetail,
  FindingSummary,
  Summary,
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
  governance: (
    id: string,
    update: { status: Asset["governance_status"]; owner?: string | null; notes?: string | null },
  ) =>
    request<{ id: string; governance_status: string; owner: string | null; notes: string | null }>(
      `/v1/inventory/assets/${id}/governance`,
      { method: "PATCH", body: JSON.stringify(update) },
    ),
};
