CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS schema_migration (
    version         text PRIMARY KEY,
    applied_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS collection_run (
    tenant_id       uuid NOT NULL,
    connector_id    text NOT NULL,
    connection_id   text NOT NULL,
    run_id           text NOT NULL,
    scope_key        text NOT NULL,
    collected_at     timestamptz NOT NULL,
    completed_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, connector_id, connection_id, run_id)
);

CREATE TABLE IF NOT EXISTS collection_coverage (
    tenant_id       uuid NOT NULL,
    connector_id    text NOT NULL,
    connection_id   text NOT NULL,
    run_id           text NOT NULL,
    plane            text NOT NULL,
    scope            text NOT NULL,
    state            text NOT NULL CHECK (
        state IN ('complete', 'partial', 'failed', 'not_supported', 'unknown')
    ),
    detail           text,
    collected_at     timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, connector_id, connection_id, run_id, plane, scope),
    FOREIGN KEY (tenant_id, connector_id, connection_id, run_id)
        REFERENCES collection_run (tenant_id, connector_id, connection_id, run_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS asset (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid NOT NULL,
    kind                text NOT NULL,
    natural_key         text NOT NULL,
    governance_status   text NOT NULL DEFAULT 'unreviewed' CHECK (
        governance_status IN ('approved', 'unreviewed', 'unwanted')
    ),
    lifecycle_state     text NOT NULL DEFAULT 'active' CHECK (
        lifecycle_state IN ('active', 'withdrawn', 'unknown')
    ),
    owner               text,
    notes               text,
    first_seen_at       timestamptz NOT NULL,
    last_seen_at        timestamptz NOT NULL,
    last_changed_at     timestamptz NOT NULL,
    UNIQUE (tenant_id, kind, natural_key)
);

CREATE INDEX IF NOT EXISTS asset_tenant_kind_idx
    ON asset (tenant_id, kind, lifecycle_state);

CREATE TABLE IF NOT EXISTS asset_assertion (
    tenant_id           uuid NOT NULL,
    asset_id            uuid NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    connector_id        text NOT NULL,
    connection_id       text NOT NULL,
    scope_key            text NOT NULL,
    coverage_plane      text NOT NULL,
    assertion_type      text NOT NULL CHECK (
        assertion_type IN ('declared', 'inferred', 'observed', 'externally_verified')
    ),
    confidence          double precision NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    display_name        text NOT NULL,
    attributes          jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence            jsonb NOT NULL,
    lifecycle_state     text NOT NULL CHECK (
        lifecycle_state IN ('active', 'withdrawn', 'unknown')
    ),
    first_seen_at       timestamptz NOT NULL,
    last_seen_at        timestamptz NOT NULL,
    last_observed_run_id text NOT NULL,
    withdrawn_at        timestamptz,
    PRIMARY KEY (
        tenant_id, asset_id, connector_id, connection_id, scope_key,
        coverage_plane, assertion_type
    )
);

CREATE INDEX IF NOT EXISTS asset_assertion_active_idx
    ON asset_assertion (tenant_id, asset_id, withdrawn_at);

CREATE TABLE IF NOT EXISTS relationship_assertion (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid NOT NULL,
    source_asset_id     uuid NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    target_asset_id     uuid NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    kind                text NOT NULL,
    category            text NOT NULL CHECK (category IN ('capability', 'influence', 'topology')),
    connector_id        text NOT NULL,
    connection_id       text NOT NULL,
    scope_key            text NOT NULL,
    coverage_plane      text NOT NULL,
    assertion_type      text NOT NULL CHECK (
        assertion_type IN ('declared', 'inferred', 'observed', 'externally_verified')
    ),
    confidence          double precision NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    attributes          jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence            jsonb NOT NULL,
    principal_asset_id  uuid REFERENCES asset(id) ON DELETE SET NULL,
    agent_asset_id      uuid REFERENCES asset(id) ON DELETE SET NULL,
    first_seen_at       timestamptz NOT NULL,
    last_seen_at        timestamptz NOT NULL,
    last_observed_run_id text NOT NULL,
    withdrawn_at        timestamptz,
    UNIQUE (
        tenant_id, source_asset_id, target_asset_id, kind, connector_id,
        connection_id, scope_key, coverage_plane, assertion_type
    )
);

CREATE INDEX IF NOT EXISTS relationship_assertion_source_idx
    ON relationship_assertion (tenant_id, source_asset_id, category, withdrawn_at);
CREATE INDEX IF NOT EXISTS relationship_assertion_target_idx
    ON relationship_assertion (tenant_id, target_asset_id, category, withdrawn_at);
