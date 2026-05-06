ALTER TABLE node_observations
    ADD COLUMN IF NOT EXISTS node_observation_id BIGSERIAL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'node_observations'::regclass
          AND conname = 'node_observations_pkey'
    ) THEN
        ALTER TABLE node_observations
            ADD CONSTRAINT node_observations_pkey PRIMARY KEY (node_observation_id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS node_observations_last_run_nodes_keyset_idx
    ON node_observations (
        crawl_run_id,
        observed_at DESC,
        endpoint ASC,
        node_observation_id DESC
    )
    WHERE protocol_version IS NOT NULL;

CREATE INDEX IF NOT EXISTS node_observations_observed_endpoint_idx
    ON node_observations (observed_at DESC, endpoint, crawl_run_id DESC);
