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

export type FindingSeverity =
  | "unknown"
  | "informational"
  | "low"
  | "medium"
  | "high"
  | "critical";

export type FindingState = "open" | "resolved" | "suppressed" | "unknown";

export type Finding = {
  id: string;
  connector_id: string;
  connection_id: string;
  scope_key: string;
  source_uid: string;
  rule_uid: string;
  title: string;
  description: string | null;
  risk: string | null;
  remediation: string | null;
  remediation_references: string[];
  severity: FindingSeverity;
  state: FindingState;
  evaluation_result: string;
  class_uid: number;
  class_name: string;
  source_observed_at: string;
  evidence: Evidence;
  attributes: Record<string, unknown>;
  resolution_reason: string | null;
  first_seen_at: string;
  last_seen_at: string;
  last_changed_at: string;
  last_observed_run_id: string;
  resource_count: number;
};

export type FindingResource = {
  uid: string;
  name: string | null;
  resource_type: string | null;
  provider: string | null;
  account_uid: string | null;
  region: string | null;
};

export type FindingObservation = {
  run_id: string;
  scope_key: string;
  collected_at: string;
  source_observed_at: string;
  severity: FindingSeverity;
  state: FindingState;
  evaluation_result: string;
  evidence: Evidence;
  attributes: Record<string, unknown>;
  affected_resources: FindingResource[];
  compliance: Record<string, string[]>;
};

export type FindingDetail = Finding & {
  resources: FindingResource[];
  compliance: Record<string, string[]>;
  observations: FindingObservation[];
};

export type FindingSummary = {
  total: number;
  by_state: Record<string, number>;
  open_by_severity: Record<string, number>;
};
