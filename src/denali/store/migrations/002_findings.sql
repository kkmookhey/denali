CREATE TABLE IF NOT EXISTS finding (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               uuid NOT NULL,
    connector_id            text NOT NULL,
    connection_id           text NOT NULL,
    scope_key               text NOT NULL,
    source_uid              text NOT NULL,
    rule_uid                text NOT NULL,
    title                   text NOT NULL,
    description             text,
    risk                    text,
    remediation             text,
    remediation_references  jsonb NOT NULL DEFAULT '[]'::jsonb,
    severity                text NOT NULL CHECK (
        severity IN ('unknown', 'informational', 'low', 'medium', 'high', 'critical')
    ),
    state                   text NOT NULL CHECK (
        state IN ('open', 'resolved', 'suppressed', 'unknown')
    ),
    evaluation_result       text NOT NULL CHECK (
        evaluation_result IN ('fail', 'pass', 'manual', 'unknown')
    ),
    class_uid               integer NOT NULL CHECK (class_uid > 2000 AND class_uid < 3000),
    class_name              text NOT NULL,
    source_observed_at      timestamptz NOT NULL,
    evidence                jsonb NOT NULL,
    attributes              jsonb NOT NULL DEFAULT '{}'::jsonb,
    resolution_reason       text,
    first_seen_at           timestamptz NOT NULL,
    last_seen_at            timestamptz NOT NULL,
    last_changed_at         timestamptz NOT NULL,
    last_observed_run_id    text NOT NULL,
    UNIQUE (tenant_id, connector_id, connection_id, source_uid)
);

CREATE INDEX IF NOT EXISTS finding_tenant_state_idx
    ON finding (tenant_id, state, severity, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS finding_source_scope_idx
    ON finding (tenant_id, connector_id, connection_id, scope_key, last_observed_run_id);

CREATE TABLE IF NOT EXISTS finding_resource (
    tenant_id       uuid NOT NULL,
    finding_id      uuid NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    resource_uid    text NOT NULL,
    resource_name   text,
    resource_type   text,
    provider        text,
    account_uid     text,
    region          text,
    PRIMARY KEY (tenant_id, finding_id, resource_uid)
);

CREATE INDEX IF NOT EXISTS finding_resource_uid_idx
    ON finding_resource (tenant_id, resource_uid);

CREATE TABLE IF NOT EXISTS finding_compliance (
    tenant_id       uuid NOT NULL,
    finding_id      uuid NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    framework       text NOT NULL,
    control         text NOT NULL,
    PRIMARY KEY (tenant_id, finding_id, framework, control)
);

CREATE TABLE IF NOT EXISTS finding_observation (
    tenant_id               uuid NOT NULL,
    finding_id              uuid NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    connector_id            text NOT NULL,
    connection_id           text NOT NULL,
    run_id                  text NOT NULL,
    scope_key               text NOT NULL,
    collected_at            timestamptz NOT NULL,
    source_observed_at      timestamptz NOT NULL,
    severity                text NOT NULL,
    state                   text NOT NULL,
    evaluation_result       text NOT NULL,
    evidence                jsonb NOT NULL,
    attributes              jsonb NOT NULL DEFAULT '{}'::jsonb,
    affected_resources      jsonb NOT NULL DEFAULT '[]'::jsonb,
    compliance              jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, finding_id, connector_id, connection_id, run_id),
    FOREIGN KEY (tenant_id, connector_id, connection_id, run_id)
        REFERENCES collection_run (tenant_id, connector_id, connection_id, run_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS finding_observation_timeline_idx
    ON finding_observation (tenant_id, finding_id, collected_at DESC);
