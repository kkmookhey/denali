CREATE TABLE IF NOT EXISTS vulnerability (
    id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                   uuid NOT NULL,
    canonical_key               text NOT NULL,
    vulnerability_id            text NOT NULL,
    component_kind              text NOT NULL,
    component_natural_key       text NOT NULL,
    component_asset_id          uuid REFERENCES asset(id) ON DELETE SET NULL,
    target_kind                 text NOT NULL,
    target_natural_key          text NOT NULL,
    target_asset_id             uuid REFERENCES asset(id) ON DELETE SET NULL,
    state                       text NOT NULL CHECK (
        state IN ('open', 'resolved', 'suppressed', 'unknown')
    ),
    resolution_reason           text,
    first_seen_at               timestamptz NOT NULL,
    last_seen_at                timestamptz NOT NULL,
    last_changed_at             timestamptz NOT NULL,
    UNIQUE (tenant_id, canonical_key)
);

CREATE INDEX IF NOT EXISTS vulnerability_tenant_state_idx
    ON vulnerability (tenant_id, state, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS vulnerability_component_idx
    ON vulnerability (tenant_id, component_asset_id);
CREATE INDEX IF NOT EXISTS vulnerability_target_idx
    ON vulnerability (tenant_id, target_asset_id);

CREATE TABLE IF NOT EXISTS vulnerability_observation (
    tenant_id                   uuid NOT NULL,
    vulnerability_id            uuid NOT NULL REFERENCES vulnerability(id) ON DELETE CASCADE,
    connector_id                text NOT NULL,
    connection_id               text NOT NULL,
    source_uid                  text NOT NULL,
    scope_key                   text NOT NULL,
    aliases                     jsonb NOT NULL DEFAULT '[]'::jsonb,
    title                       text,
    description                 text,
    severity                    text NOT NULL CHECK (
        severity IN ('unknown', 'informational', 'low', 'medium', 'high', 'critical')
    ),
    state                       text NOT NULL CHECK (
        state IN ('open', 'resolved', 'suppressed', 'unknown')
    ),
    cvss_score                  double precision CHECK (
        cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)
    ),
    cvss_vector                 text,
    fix_state                   text NOT NULL CHECK (
        fix_state IN ('fixed', 'not_fixed', 'wont_fix', 'unknown')
    ),
    fixed_versions              jsonb NOT NULL DEFAULT '[]'::jsonb,
    exploit_state               text NOT NULL CHECK (
        exploit_state IN ('known_exploited', 'public_exploit', 'no_known_exploit', 'unknown')
    ),
    match_method                text NOT NULL CHECK (
        match_method IN ('exact_direct', 'exact_indirect', 'distro', 'ecosystem', 'cpe',
                         'unknown')
    ),
    match_confidence            double precision NOT NULL CHECK (
        match_confidence >= 0 AND match_confidence <= 1
    ),
    database_version            text,
    database_built_at           timestamptz,
    source_observed_at          timestamptz NOT NULL,
    evidence                    jsonb NOT NULL,
    attributes                  jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at               timestamptz NOT NULL,
    last_seen_at                timestamptz NOT NULL,
    last_observed_run_id        text NOT NULL,
    withdrawn_at                timestamptz,
    PRIMARY KEY (tenant_id, connector_id, connection_id, source_uid),
    FOREIGN KEY (tenant_id, connector_id, connection_id, last_observed_run_id)
        REFERENCES collection_run (tenant_id, connector_id, connection_id, run_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS vulnerability_observation_current_idx
    ON vulnerability_observation (tenant_id, vulnerability_id, withdrawn_at);
CREATE INDEX IF NOT EXISTS vulnerability_observation_source_idx
    ON vulnerability_observation (
        tenant_id, connector_id, connection_id, scope_key, last_observed_run_id
    );
