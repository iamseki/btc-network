use std::env;

use serde::Serialize;
use utoipa::Modify;
use utoipa::ToSchema;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::openapi::server::ServerBuilder;

pub const OPENAPI_PATH: &str = "/api/openapi.json";
pub const DOCS_CONFIG_PATH: &str = "/api/docs/config.json";
pub const SCALAR_PATH: &str = "/docs";

const DEFAULT_DOCS_TITLE: &str = "btc-network API";
const DEFAULT_DOCS_DESCRIPTION: &str = "Read-only Bitcoin network analytics API for historical run inspection, historical ASN concentration, last-run snapshot slices, protocol distributions, and verified node summaries. The OpenAPI specification is generated from the live Rust handlers so hosted Scalar docs, web-embedded API reference views, and downstream tooling stay aligned with the real contract.";
const DEFAULT_DOCS_INTRODUCTION: &str = "Start with historical runs to inspect previous network snapshots and outcomes, compare historical ASN concentration when needed, then drill into last-run analytics for transport mix, services, user agents, countries, and verified nodes.";
const DOCS_TITLE_ENV: &str = "BTC_NETWORK_API_DOCS_TITLE";
const DOCS_VERSION_ENV: &str = "BTC_NETWORK_API_DOCS_VERSION";
const DOCS_DESCRIPTION_ENV: &str = "BTC_NETWORK_API_DOCS_DESCRIPTION";
const DOCS_INTRODUCTION_ENV: &str = "BTC_NETWORK_API_DOCS_INTRODUCTION";
const PUBLIC_BASE_URL_ENV: &str = "BTC_NETWORK_API_PUBLIC_BASE_URL";

#[derive(Clone, Debug)]
pub struct DocsConfig {
    title: String,
    version: String,
    description: String,
    introduction: String,
    public_base_url: Option<String>,
}

impl Default for DocsConfig {
    fn default() -> Self {
        Self {
            title: DEFAULT_DOCS_TITLE.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            description: DEFAULT_DOCS_DESCRIPTION.to_string(),
            introduction: DEFAULT_DOCS_INTRODUCTION.to_string(),
            public_base_url: None,
        }
    }
}

impl DocsConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            title: parse_non_empty_env(DOCS_TITLE_ENV)
                .unwrap_or_else(|| DEFAULT_DOCS_TITLE.to_string()),
            version: parse_non_empty_env(DOCS_VERSION_ENV)
                .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()),
            description: parse_non_empty_env(DOCS_DESCRIPTION_ENV)
                .unwrap_or_else(|| DEFAULT_DOCS_DESCRIPTION.to_string()),
            introduction: parse_non_empty_env(DOCS_INTRODUCTION_ENV)
                .unwrap_or_else(|| DEFAULT_DOCS_INTRODUCTION.to_string()),
            public_base_url: parse_optional_url_env(PUBLIC_BASE_URL_ENV)?,
        })
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn public_base_url(&self) -> Option<&str> {
        self.public_base_url.as_deref()
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn introduction(&self) -> &str {
        &self.introduction
    }

    pub fn openapi_url(&self) -> String {
        join_url(self.public_base_url(), OPENAPI_PATH)
    }

    pub fn scalar_ui_config(&self) -> DocsUiConfigResponse {
        DocsUiConfigResponse {
            title: self.title.clone(),
            version: self.version.clone(),
            description: self.description.clone(),
            introduction: self.introduction.clone(),
            openapi_url: self.openapi_url(),
            openapi_path: OPENAPI_PATH.to_string(),
            scalar_path: SCALAR_PATH.to_string(),
            base_server_url: self.public_base_url.clone(),
        }
    }
}

impl Modify for DocsConfig {
    fn modify(&self, openapi: &mut OpenApiDocument) {
        openapi.info.title = self.title.clone();
        openapi.info.version = self.version.clone();
        openapi.info.description = Some(self.description.clone());

        openapi.servers = self
            .public_base_url
            .as_ref()
            .map(|base_url| vec![ServerBuilder::new().url(base_url).build()]);
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DocsUiConfigResponse {
    title: String,
    version: String,
    description: String,
    introduction: String,
    openapi_url: String,
    openapi_path: String,
    scalar_path: String,
    base_server_url: Option<String>,
}

fn parse_non_empty_env(name: &str) -> Option<String> {
    env::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn parse_optional_url_env(name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(value) = parse_non_empty_env(name) else {
        return Ok(None);
    };

    let parsed = url::Url::parse(&value)?;
    Ok(Some(parsed.to_string().trim_end_matches('/').to_string()))
}

fn join_url(base_url: Option<&str>, path: &str) -> String {
    match base_url {
        Some(base_url) => format!("{base_url}{path}"),
        None => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utoipa::openapi::OpenApi;

    #[test]
    fn docs_config_defaults_to_package_version() {
        let config = DocsConfig::default();

        assert_eq!(config.title(), DEFAULT_DOCS_TITLE);
        assert_eq!(config.version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(config.description(), DEFAULT_DOCS_DESCRIPTION);
        assert_eq!(config.introduction(), DEFAULT_DOCS_INTRODUCTION);
        assert_eq!(config.openapi_url(), OPENAPI_PATH);
    }

    #[test]
    fn docs_config_response_uses_public_base_url() {
        let config = DocsConfig {
            title: "btc-network public api".to_string(),
            version: "2026.04".to_string(),
            description: "Generated OpenAPI for the public Bitcoin analytics API.".to_string(),
            introduction: "Start with runs, then drill into latest-run views.".to_string(),
            public_base_url: Some("https://api.btcnetwork.info".to_string()),
        };

        let response = config.scalar_ui_config();

        assert_eq!(
            response.openapi_url,
            "https://api.btcnetwork.info/api/openapi.json"
        );
        assert_eq!(
            response.base_server_url.as_deref(),
            Some("https://api.btcnetwork.info")
        );
        assert_eq!(
            response.description,
            "Generated OpenAPI for the public Bitcoin analytics API."
        );
        assert_eq!(
            response.introduction,
            "Start with runs, then drill into latest-run views."
        );
    }

    #[test]
    fn docs_config_modify_updates_openapi_metadata() {
        let config = DocsConfig {
            title: "btc-network public api".to_string(),
            version: "2026.04".to_string(),
            description: "Generated OpenAPI for the public Bitcoin analytics API.".to_string(),
            introduction: "Start with runs, then drill into latest-run views.".to_string(),
            public_base_url: Some("https://api.btcnetwork.info".to_string()),
        };
        let mut openapi = OpenApi::default();

        config.modify(&mut openapi);

        assert_eq!(openapi.info.title, "btc-network public api");
        assert_eq!(openapi.info.version, "2026.04");
        assert_eq!(
            openapi.info.description.as_deref(),
            Some("Generated OpenAPI for the public Bitcoin analytics API.")
        );
        assert_eq!(
            openapi.servers.expect("servers")[0].url,
            "https://api.btcnetwork.info"
        );
    }
}
