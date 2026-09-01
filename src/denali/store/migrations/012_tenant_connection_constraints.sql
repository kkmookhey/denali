CREATE UNIQUE INDEX IF NOT EXISTS provider_connection_tenant_id_id_idx
    ON provider_connection (tenant_id, id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'connection_validation_tenant_connection_fk'
    ) THEN
        ALTER TABLE connection_validation
            ADD CONSTRAINT connection_validation_tenant_connection_fk
            FOREIGN KEY (tenant_id, connection_id)
            REFERENCES provider_connection (tenant_id, id) ON DELETE CASCADE;
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'connection_validation_job_tenant_connection_fk'
    ) THEN
        ALTER TABLE connection_validation_job
            ADD CONSTRAINT connection_validation_job_tenant_connection_fk
            FOREIGN KEY (tenant_id, connection_id)
            REFERENCES provider_connection (tenant_id, id) ON DELETE CASCADE;
    END IF;
END
$$;
