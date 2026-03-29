use btc_network::crawler::{CountNodesByAsnRow, CrawlerRepositoryError};
use clickhouse::{Client, sql::Identifier};

use crate::rows::{CountNodesByAsnDbRow, to_count_nodes_by_asn};

use super::{NODE_OBSERVATIONS_TABLE, map_clickhouse_err};

pub(super) async fn count_nodes_by_asn(
    client: &Client,
) -> Result<Vec<CountNodesByAsnRow>, CrawlerRepositoryError> {
    client
        .query(
            "
SELECT
    asn,
    asn_organization,
    count() AS verified_nodes
FROM (
    SELECT
        endpoint,
        argMax(confidence_level, tuple(observed_at, observation_id)) AS confidence_level,
        argMax(asn, tuple(observed_at, observation_id)) AS asn,
        argMax(asn_organization, tuple(observed_at, observation_id)) AS asn_organization
    FROM ?
    GROUP BY endpoint
)
WHERE confidence_level = 'verified'
GROUP BY asn, asn_organization
ORDER BY verified_nodes DESC, asn ASC
",
        )
        .bind(Identifier(NODE_OBSERVATIONS_TABLE))
        .fetch_all::<CountNodesByAsnDbRow>()
        .await
        .map(|rows| rows.into_iter().map(to_count_nodes_by_asn).collect())
        .map_err(map_clickhouse_err("count nodes by ASN"))
}
