export type Asset = {
  id: string;
  kind: string;
  natural_key: string;
  governance_status: "approved" | "unreviewed" | "unwanted";
  lifecycle_state: string;
  owner: string | null;
  first_seen_at: string;
  last_seen_at: string;
  last_changed_at: string;
  display_name: string | null;
  attributes: Record<string, unknown> | null;
  assertion_type: string | null;
  confidence: number | null;
  connector_id: string | null;
  connection_id: string | null;
};

export type Evidence = {
  source_type: string;
  locator: string;
  observed_at: string;
  payload: Record<string, unknown>;
};

export type AssetAssertion = {
  connector_id: string;
  connection_id: string;
  scope_key: string;
  coverage_plane: string;
  assertion_type: string;
  confidence: number;
  display_name: string;
  attributes: Record<string, unknown>;
  evidence: Evidence;
  lifecycle_state: string;
  first_seen_at: string;
  last_seen_at: string;
  withdrawn_at: string | null;
};

export type Relationship = {
  id: string;
  kind: string;
  category: string;
  assertion_type: string;
  confidence: number;
  attributes: Record<string, unknown>;
  evidence: Evidence;
  withdrawn_at: string | null;
  source_id: string;
  source_kind: string;
  source_natural_key: string;
  target_id: string;
  target_kind: string;
  target_natural_key: string;
};

export type AssetDetail = Asset & {
  tenant_id: string;
  notes: string | null;
  assertions: AssetAssertion[];
  relationships: Relationship[];
};

export type Summary = {
  total: number;
  by_kind: Record<string, number>;
  by_governance: Record<string, number>;
};

export type Coverage = {
  connector_id: string;
  connection_id: string;
  plane: string;
  scope: string;
  state: "complete" | "partial" | "failed" | "not_supported" | "unknown";
  detail: string | null;
  run_id: string;
  collected_at: string;
};
