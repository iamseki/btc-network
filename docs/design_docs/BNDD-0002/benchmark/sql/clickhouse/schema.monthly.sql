CREATE DATABASE IF NOT EXISTS btc_bench;
USE btc_bench;

DROP TABLE IF EXISTS node_observations;

-- Synthetic crawler observations for the BNDD-0002 benchmark.
--
-- Field notes for the less obvious columns:
-- - relay: whether the peer advertises transaction relay support in the version handshake.
--   It is useful as a small example of handshake-derived node capability metadata.
-- - asn: the Autonomous System Number derived from IP enrichment. This is a key dimension
--   for infrastructure concentration analysis because ASN/operator concentration matters
--   more than country alone for Bitcoin network risk analysis.
-- - prefix: a simplified network grouping such as an IPv4 /16 bucket. It approximates
--   subnet clustering so we can test concentration queries without requiring a full IP type.
-- - latency_ms: synthetic connect/handshake latency in milliseconds. This is included to
--   keep the benchmark schema close to plausible crawler telemetry and to leave room for
--   future percentiles/time-series latency analysis.
-- - discovered_count: how many peer addresses a node returned during getaddr/addrv2 style
--   discovery. This helps model node usefulness and address-gossip intensity.
--
-- ClickHouse-specific type rationale:
-- - LowCardinality(String): ClickHouse stores repeated string values through dictionary
--   encoding. It is a good fit for columns like network_type, handshake_status,
--   confidence_level, and user_agent because those values repeat often across many rows.
--   This usually reduces storage and can improve grouping/filtering performance.
-- - FixedString(2): country codes are always two bytes in this synthetic schema.
-- - ENGINE = MergeTree: "engine" in ClickHouse defines the physical storage behavior of the
--   table. MergeTree is the standard general-purpose engine for large analytical tables.
--   It supports ordered storage, partitioning, efficient scans, and background merges.
-- - PARTITION BY toYYYYMM(observed_at): uses monthly partitions as the production-oriented
--   default for a system that may run for years. It avoids an excessive number of tiny
--   partitions while still allowing useful time pruning. A daily variant is still worth
--   benchmarking separately if recent-window scans dominate.
-- - ORDER BY (observed_at, endpoint, asn): defines the primary sort key on disk. This is
--   chosen to favor time-range scans first while keeping endpoint/latest-state and ASN
--   analytics reasonably local in storage.
CREATE TABLE node_observations (
    observed_at DateTime,
    crawl_run_id UInt64,
    endpoint String,
    network_type LowCardinality(String),
    handshake_status LowCardinality(String),
    confidence_level LowCardinality(String),
    protocol_version UInt32,
    services UInt64,
    user_agent LowCardinality(String),
    start_height UInt32,
    relay Bool,
    asn UInt32,
    country_code FixedString(2),
    prefix String,
    latency_ms UInt32,
    discovered_count UInt32
) ENGINE = MergeTree
PARTITION BY toYYYYMM(observed_at)
ORDER BY (observed_at, endpoint, asn);
