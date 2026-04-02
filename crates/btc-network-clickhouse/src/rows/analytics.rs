use btc_network::crawler::{
    AsnNodeCountItem, CountNodesByAsnRow, FailureClassificationCount, NetworkOutcomeCount,
};
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

pub(crate) fn to_asn_node_count_item(row: CountNodesByAsnDbRow) -> AsnNodeCountItem {
    AsnNodeCountItem {
        asn: row.asn,
        asn_organization: row.asn_organization,
        verified_nodes: row.verified_nodes,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Row, Serialize, Deserialize)]
pub(crate) struct FailureClassificationCountDbRow {
    pub classification: String,
    pub observations: u64,
}

pub(crate) fn to_failure_classification_count(
    row: FailureClassificationCountDbRow,
) -> FailureClassificationCount {
    FailureClassificationCount {
        classification: row.classification,
        observations: row.observations,
    }
}

#[derive(Debug, Clone, PartialEq, Row, Serialize, Deserialize)]
pub(crate) struct NetworkOutcomeCountDbRow {
    pub network_type: String,
    pub observations: u64,
    pub verified_nodes: u64,
    pub failed_nodes: u64,
    pub verified_pct: f64,
}

pub(crate) fn to_network_outcome_count(row: NetworkOutcomeCountDbRow) -> NetworkOutcomeCount {
    NetworkOutcomeCount {
        network_type: row.network_type,
        observations: row.observations,
        verified_nodes: row.verified_nodes,
        failed_nodes: row.failed_nodes,
        verified_pct: row.verified_pct,
    }
}
