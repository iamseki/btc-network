pub(crate) mod asn_organizations;
pub(crate) mod asns;
pub(crate) mod countries;
pub(crate) mod network_types;
pub(crate) mod nodes;
pub(crate) mod protocol_versions;
pub(crate) mod services;
pub(crate) mod start_heights;
pub(crate) mod user_agents;

pub(crate) use asn_organizations::{
    LIST_LAST_RUN_ASN_ORGANIZATIONS_PATH, list_last_run_asn_organizations,
};
pub(crate) use asns::{LIST_LAST_RUN_ASNS_PATH, list_last_run_asns};
pub(crate) use countries::{LIST_LAST_RUN_COUNTRIES_PATH, list_last_run_countries};
pub(crate) use network_types::{LIST_LAST_RUN_NETWORK_TYPES_PATH, list_last_run_network_types};
pub(crate) use nodes::{LIST_LAST_RUN_NODES_PATH, list_last_run_nodes};
pub(crate) use protocol_versions::{
    LIST_LAST_RUN_PROTOCOL_VERSIONS_PATH, list_last_run_protocol_versions,
};
pub(crate) use services::{LIST_LAST_RUN_SERVICES_PATH, list_last_run_services};
pub(crate) use start_heights::{LIST_LAST_RUN_START_HEIGHTS_PATH, list_last_run_start_heights};
pub(crate) use user_agents::{LIST_LAST_RUN_USER_AGENTS_PATH, list_last_run_user_agents};

use btc_network::crawler::{CrawlPhase, CrawlRunPhaseFilter};
use serde::Deserialize;

use crate::handlers::ApiError;

#[derive(Debug, Deserialize)]
pub(crate) struct LastRunDistributionQuery {
    pub(crate) limit: Option<usize>,
    pub(crate) phase: Option<String>,
}

pub(crate) fn parse_phase_filter(value: Option<String>) -> Result<CrawlRunPhaseFilter, ApiError> {
    let Some(value) = value else {
        return Ok(CrawlRunPhaseFilter::Finished);
    };

    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "finished" {
        return Ok(CrawlRunPhaseFilter::Finished);
    }

    if trimmed == "any" {
        return Ok(CrawlRunPhaseFilter::Any);
    }

    let phases = trimmed
        .split(',')
        .map(str::trim)
        .filter(|phase| !phase.is_empty())
        .map(|phase| match phase {
            "bootstrap" => Ok(CrawlPhase::Bootstrap),
            "crawling" => Ok(CrawlPhase::Crawling),
            "draining" => Ok(CrawlPhase::Draining),
            "finished" => Ok(CrawlPhase::Finished),
            _ => Err(ApiError::bad_request(
                "phase must be one of any, bootstrap, crawling, draining, or finished",
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;

    if phases.is_empty() {
        return Ok(CrawlRunPhaseFilter::Finished);
    }

    Ok(CrawlRunPhaseFilter::OneOf(phases))
}
