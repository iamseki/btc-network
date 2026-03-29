use btc_network::crawler::CountNodesByAsnRow;
use clickhouse::Row;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Row, Serialize, Deserialize)]
pub(crate) struct CountNodesByAsnDbRow {
    pub asn: Option<u32>,
    pub asn_organization: Option<String>,
    pub verified_nodes: u64,
}

pub(crate) fn to_count_nodes_by_asn(row: CountNodesByAsnDbRow) -> CountNodesByAsnRow {
    CountNodesByAsnRow {
        asn: row.asn,
        asn_organization: row.asn_organization,
        verified_nodes: row.verified_nodes,
    }
}
