CREATE TABLE IF NOT EXISTS runtime_detection (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               uuid NOT NULL,
    correlation_key         text NOT NULL,
    rule_uid                text NOT NULL,
    title                   text NOT NULL,
    description             text NOT NULL,
    risk                    text NOT NULL,
    investigation_guidance  text NOT NULL,
    severity                text NOT NULL CHECK (
        severity IN ('unknown', 'informational', 'low', 'medium', 'high', 'critical')
    ),
    state                   text NOT NULL CHECK (state IN ('open', 'resolved', 'unknown')),
    confidence              double precision NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    attributes              jsonb NOT NULL DEFAULT '{}'::jsonb,
    resolution_reason       text,
    first_seen_at           timestamptz NOT NULL,
    last_seen_at            timestamptz NOT NULL,
    last_changed_at         timestamptz NOT NULL,
    last_evaluated_at       timestamptz NOT NULL,
    UNIQUE (tenant_id, correlation_key)
);

CREATE INDEX IF NOT EXISTS runtime_detection_tenant_state_idx
    ON runtime_detection (tenant_id, state, severity, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS runtime_detection_activity (
    tenant_id       uuid NOT NULL,
    detection_id    uuid NOT NULL REFERENCES runtime_detection(id) ON DELETE CASCADE,
    activity_id     uuid NOT NULL REFERENCES activity_event(id) ON DELETE RESTRICT,
    role            text NOT NULL,
    PRIMARY KEY (tenant_id, detection_id, activity_id)
);

CREATE TABLE IF NOT EXISTS runtime_detection_asset (
    tenant_id       uuid NOT NULL,
    detection_id    uuid NOT NULL REFERENCES runtime_detection(id) ON DELETE CASCADE,
    asset_id        uuid NOT NULL REFERENCES asset(id) ON DELETE RESTRICT,
    role            text NOT NULL,
    PRIMARY KEY (tenant_id, detection_id, asset_id, role)
);

CREATE TABLE IF NOT EXISTS runtime_detection_rule_evaluation (
    tenant_id                   uuid NOT NULL,
    rule_uid                    text NOT NULL,
    state                       text NOT NULL CHECK (
        state IN ('complete', 'partial', 'failed', 'not_supported', 'unknown')
    ),
    confirmed_detections        integer NOT NULL CHECK (confirmed_detections >= 0),
    incomplete_candidates       integer NOT NULL CHECK (incomplete_candidates >= 0),
    detail                      text,
    evaluated_at                timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, rule_uid)
);

UPDATE activity_event
SET attributes = attributes
    || jsonb_build_object(
        'activity_operation', evidence #>> '{payload,activityDisplayName}',
        'correlation_id', evidence #>> '{payload,correlationId}'
    )
WHERE category = 'admin_change'
  AND evidence #>> '{payload,activityDisplayName}' IS NOT NULL
  AND NOT (attributes ? 'activity_operation');
