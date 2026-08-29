CREATE TABLE IF NOT EXISTS provider_connection (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               uuid NOT NULL,
    provider                text NOT NULL,
    display_name            text NOT NULL,
    lifecycle_state         text NOT NULL DEFAULT 'active' CHECK (
        lifecycle_state IN ('active', 'disabled')
    ),
    health_state            text NOT NULL DEFAULT 'unknown' CHECK (
        health_state IN ('unknown', 'healthy', 'partial', 'unhealthy', 'disabled')
    ),
    credential_type         text NOT NULL,
    credential_reference    jsonb NOT NULL,
    declared_scopes         jsonb NOT NULL DEFAULT '[]'::jsonb,
    coverage_plan           jsonb NOT NULL DEFAULT '[]'::jsonb,
    configuration           jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    last_validated_at       timestamptz,
    UNIQUE (tenant_id, provider, display_name)
);

CREATE INDEX IF NOT EXISTS provider_connection_tenant_idx
    ON provider_connection (tenant_id, provider, lifecycle_state, display_name);

CREATE TABLE IF NOT EXISTS connection_validation (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               uuid NOT NULL,
    connection_id           uuid NOT NULL REFERENCES provider_connection(id) ON DELETE CASCADE,
    started_at              timestamptz NOT NULL,
    completed_at            timestamptz NOT NULL,
    health_state            text NOT NULL CHECK (
        health_state IN ('healthy', 'partial', 'unhealthy')
    ),
    credential_state        text NOT NULL CHECK (
        credential_state IN ('passed', 'failed')
    ),
    account_id_observed     text,
    results                 jsonb NOT NULL DEFAULT '[]'::jsonb,
    summary                 text NOT NULL,
    created_at              timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS connection_validation_latest_idx
    ON connection_validation (tenant_id, connection_id, completed_at DESC);
