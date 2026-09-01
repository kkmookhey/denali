CREATE TABLE IF NOT EXISTS denali_tenant (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    clerk_organization_id   text NOT NULL UNIQUE CHECK (
        clerk_organization_id ~ '^org_[A-Za-z0-9]+$'
    ),
    created_at              timestamptz NOT NULL DEFAULT now(),
    last_seen_at            timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS provider_connection_tenant_id_id_idx
    ON provider_connection (tenant_id, id);

CREATE TABLE IF NOT EXISTS connection_validation_job (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               uuid NOT NULL,
    connection_id           uuid NOT NULL,
    state                   text NOT NULL DEFAULT 'queued' CHECK (
        state IN ('queued', 'running', 'succeeded', 'failed')
    ),
    wait_for_credentials    boolean NOT NULL DEFAULT false,
    wait_for_healthy        boolean NOT NULL DEFAULT false,
    attempt_count           integer NOT NULL DEFAULT 0,
    modal_call_id           text,
    error_summary           text,
    created_at              timestamptz NOT NULL DEFAULT now(),
    started_at              timestamptz,
    completed_at            timestamptz,
    lease_expires_at        timestamptz,
    CONSTRAINT connection_validation_job_tenant_connection_fk
        FOREIGN KEY (tenant_id, connection_id)
        REFERENCES provider_connection (tenant_id, id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS connection_validation_job_active_idx
    ON connection_validation_job (tenant_id, connection_id)
    WHERE state IN ('queued', 'running');

CREATE INDEX IF NOT EXISTS connection_validation_job_status_idx
    ON connection_validation_job (tenant_id, state, created_at DESC);
