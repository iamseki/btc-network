USE btc_bench;

SELECT 'q1_hourly_handshakes_by_network_type_last_7d';
SELECT
    toStartOfHour(observed_at) AS bucket,
    network_type,
    count() AS observations
FROM node_observations
WHERE observed_at >= now() - toIntervalDay(7)
  AND handshake_status = 'verified_handshake'
GROUP BY bucket, network_type
ORDER BY bucket, network_type;

SELECT 'q2_top_10_asns_last_24h';
SELECT
    asn,
    count() AS verified_observations
FROM node_observations
WHERE observed_at >= now() - toIntervalHour(24)
  AND handshake_status = 'verified_handshake'
  AND asn != 0
GROUP BY asn
ORDER BY verified_observations DESC
LIMIT 10;

SELECT 'q3_latest_version_adoption';
SELECT
    protocol_version,
    count() AS endpoints
FROM (
    SELECT
        endpoint,
        argMax(protocol_version, observed_at) AS protocol_version
    FROM node_observations
    GROUP BY endpoint
)
GROUP BY protocol_version
ORDER BY endpoints DESC;

SELECT 'q4_daily_new_endpoints';
SELECT
    toDate(first_observed_at) AS day,
    count() AS new_endpoints
FROM (
    SELECT
        endpoint,
        min(observed_at) AS first_observed_at
    FROM node_observations
    GROUP BY endpoint
)
GROUP BY day
ORDER BY day;

SELECT 'q5_reachable_to_rumored_ratio_by_day';
SELECT
    toDate(observed_at) AS day,
    countIf(handshake_status = 'verified_handshake') AS verified_count,
    countIf(handshake_status = 'gossiped_only') AS rumored_count
FROM node_observations
GROUP BY day
ORDER BY day;

SELECT 'q6_prefix_concentration_last_7d';
SELECT
    prefix,
    count() AS observations
FROM node_observations
WHERE observed_at >= now() - toIntervalDay(7)
  AND prefix != 'overlay'
GROUP BY prefix
ORDER BY observations DESC
LIMIT 20;

SELECT 'q7_latest_state_by_handshake_status';
SELECT
    handshake_status,
    count() AS endpoints
FROM (
    SELECT
        endpoint,
        argMax(handshake_status, observed_at) AS handshake_status
    FROM node_observations
    GROUP BY endpoint
)
GROUP BY handshake_status
ORDER BY endpoints DESC;
