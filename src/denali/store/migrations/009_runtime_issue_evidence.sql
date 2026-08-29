CREATE TABLE IF NOT EXISTS issue_detection (
    tenant_id       uuid NOT NULL,
    issue_id        uuid NOT NULL REFERENCES issue(id) ON DELETE CASCADE,
    detection_id    uuid NOT NULL REFERENCES runtime_detection(id) ON DELETE RESTRICT,
    role            text NOT NULL,
    PRIMARY KEY (tenant_id, issue_id, detection_id)
);

CREATE TABLE IF NOT EXISTS issue_activity (
    tenant_id       uuid NOT NULL,
    issue_id        uuid NOT NULL REFERENCES issue(id) ON DELETE CASCADE,
    activity_id     uuid NOT NULL REFERENCES activity_event(id) ON DELETE RESTRICT,
    role            text NOT NULL,
    PRIMARY KEY (tenant_id, issue_id, activity_id)
);
