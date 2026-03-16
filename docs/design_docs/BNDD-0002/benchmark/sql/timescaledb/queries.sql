\timing on

\echo 'q1_hourly_handshakes_by_network_type_last_7d'
SELECT
    time_bucket(INTERVAL '1 hour', observed_at) AS bucket,
    network_type,
    count(*) AS observations
FROM node_observations
WHERE observed_at >= NOW() - INTERVAL '7 days'
  AND handshake_status = 'verified_handshake'
GROUP BY bucket, network_type
ORDER BY bucket, network_type;

\echo 'q2_top_10_asns_last_24h'
SELECT
    asn,
    count(*) AS verified_observations
FROM node_observations
WHERE observed_at >= NOW() - INTERVAL '24 hours'
  AND handshake_status = 'verified_handshake'
  AND asn <> 0
GROUP BY asn
ORDER BY verified_observations DESC
LIMIT 10;

\echo 'q3_latest_version_adoption'
WITH latest AS (
    SELECT DISTINCT ON (endpoint)
        endpoint,
        protocol_version
    FROM node_observations
    ORDER BY endpoint, observed_at DESC
)
SELECT
    protocol_version,
    count(*) AS endpoints
FROM latest
GROUP BY protocol_version
ORDER BY endpoints DESC;

\echo 'q4_daily_new_endpoints'
WITH first_seen AS (
    SELECT
        endpoint,
        MIN(observed_at) AS first_observed_at
    FROM node_observations
    GROUP BY endpoint
)
SELECT
    date_trunc('day', first_observed_at) AS day,
    count(*) AS new_endpoints
FROM first_seen
GROUP BY day
ORDER BY day;

\echo 'q5_reachable_to_rumored_ratio_by_day'
SELECT
    date_trunc('day', observed_at) AS day,
    count(*) FILTER (WHERE handshake_status = 'verified_handshake') AS verified_count,
    count(*) FILTER (WHERE handshake_status = 'gossiped_only') AS rumored_count
FROM node_observations
GROUP BY day
ORDER BY day;

\echo 'q6_prefix_concentration_last_7d'
SELECT
    prefix,
    count(*) AS observations
FROM node_observations
WHERE observed_at >= NOW() - INTERVAL '7 days'
  AND prefix <> 'overlay'
GROUP BY prefix
ORDER BY observations DESC
LIMIT 20;

\echo 'q7_latest_state_by_handshake_status'
WITH latest AS (
    SELECT DISTINCT ON (endpoint)
        endpoint,
        handshake_status
    FROM node_observations
    ORDER BY endpoint, observed_at DESC
)
SELECT
    handshake_status,
    count(*) AS endpoints
FROM latest
GROUP BY handshake_status
ORDER BY endpoints DESC;
