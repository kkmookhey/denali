CREATE TABLE IF NOT EXISTS activity_event (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    connector_id text NOT NULL,
    connection_id text NOT NULL,
    run_id text NOT NULL,
    scope_key text NOT NULL,
    source_uid text NOT NULL,
    category text NOT NULL,
    activity_name text NOT NULL,
    title text NOT NULL,
    outcome text NOT NULL,
    provider text NOT NULL,
    account_uid text,
    region text,
    occurred_at timestamptz NOT NULL,
    source_observed_at timestamptz NOT NULL,
    session_uid text,
    trace_uid text,
    evidence jsonb NOT NULL,
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
    ingested_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, connector_id, connection_id, source_uid),
    CHECK (category IN ('model_invocation', 'agent_invocation', 'retrieval',
                        'tool_invocation', 'ai_app_sign_in', 'admin_change',
                        'data_access', 'other')),
    CHECK (outcome IN ('success', 'failure', 'unknown'))
);

CREATE INDEX IF NOT EXISTS activity_event_tenant_time_idx
    ON activity_event (tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS activity_event_tenant_category_idx
    ON activity_event (tenant_id, category, occurred_at DESC);

CREATE TABLE IF NOT EXISTS activity_entity (
    tenant_id uuid NOT NULL,
    activity_id uuid NOT NULL REFERENCES activity_event(id) ON DELETE CASCADE,
    position integer NOT NULL,
    role text NOT NULL,
    external_uid text NOT NULL,
    display_name text,
    asset_kind text,
    asset_natural_key text,
    asset_id uuid REFERENCES asset(id) ON DELETE SET NULL,
    correlation text NOT NULL,
    confidence double precision NOT NULL,
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, activity_id, position),
    CHECK (role IN ('actor', 'agent', 'model', 'tool', 'workload', 'resource', 'application')),
    CHECK (correlation IN ('exact_identifier', 'explicit_context', 'unresolved')),
    CHECK (confidence >= 0.0 AND confidence <= 1.0),
    CHECK ((asset_kind IS NULL) = (asset_natural_key IS NULL))
);

CREATE INDEX IF NOT EXISTS activity_entity_asset_idx
    ON activity_entity (tenant_id, asset_id) WHERE asset_id IS NOT NULL;
