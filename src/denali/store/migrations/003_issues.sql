CREATE TABLE IF NOT EXISTS issue (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid NOT NULL,
    correlation_key     text NOT NULL,
    rule_uid            text NOT NULL,
    title               text NOT NULL,
    description         text NOT NULL,
    risk                text NOT NULL,
    remediation         text NOT NULL,
    severity            text NOT NULL CHECK (
        severity IN ('unknown', 'informational', 'low', 'medium', 'high', 'critical')
    ),
    state               text NOT NULL CHECK (state IN ('open', 'resolved', 'unknown')),
    confidence          double precision NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    attributes          jsonb NOT NULL DEFAULT '{}'::jsonb,
    resolution_reason   text,
    first_seen_at       timestamptz NOT NULL,
    last_seen_at        timestamptz NOT NULL,
    last_changed_at     timestamptz NOT NULL,
    last_evaluated_at   timestamptz NOT NULL,
    UNIQUE (tenant_id, correlation_key)
);

CREATE INDEX IF NOT EXISTS issue_tenant_state_idx
    ON issue (tenant_id, state, severity, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS issue_finding (
    tenant_id       uuid NOT NULL,
    issue_id        uuid NOT NULL REFERENCES issue(id) ON DELETE CASCADE,
    finding_id      uuid NOT NULL REFERENCES finding(id) ON DELETE RESTRICT,
    role            text NOT NULL,
    PRIMARY KEY (tenant_id, issue_id, finding_id)
);

CREATE TABLE IF NOT EXISTS issue_path_node (
    tenant_id       uuid NOT NULL,
    issue_id        uuid NOT NULL REFERENCES issue(id) ON DELETE CASCADE,
    position        integer NOT NULL CHECK (position >= 0),
    asset_id        uuid NOT NULL REFERENCES asset(id) ON DELETE RESTRICT,
    role            text NOT NULL,
    PRIMARY KEY (tenant_id, issue_id, position),
    UNIQUE (tenant_id, issue_id, asset_id, role)
);

CREATE TABLE IF NOT EXISTS issue_path_edge (
    tenant_id           uuid NOT NULL,
    issue_id            uuid NOT NULL REFERENCES issue(id) ON DELETE CASCADE,
    position            integer NOT NULL CHECK (position >= 0),
    relationship_id     uuid NOT NULL REFERENCES relationship_assertion(id) ON DELETE RESTRICT,
    PRIMARY KEY (tenant_id, issue_id, position),
    UNIQUE (tenant_id, issue_id, relationship_id)
);

CREATE TABLE IF NOT EXISTS issue_rule_evaluation (
    tenant_id                       uuid NOT NULL,
    rule_uid                        text NOT NULL,
    state                           text NOT NULL CHECK (
        state IN ('complete', 'partial', 'failed', 'not_supported', 'unknown')
    ),
    confirmed_issues                integer NOT NULL CHECK (confirmed_issues >= 0),
    incomplete_candidates           integer NOT NULL CHECK (incomplete_candidates >= 0),
    ambiguous_resource_references   integer NOT NULL CHECK (
        ambiguous_resource_references >= 0
    ),
    detail                          text,
    evaluated_at                    timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, rule_uid)
);
