use std::error::Error;
use std::fmt::{Display, Formatter};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::net::{TcpStream as AsyncTcpStream, lookup_host};
use tokio::time::{sleep, timeout};
use tracing::debug;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

use crate::session::AsyncSession;

const DEFAULT_ATTEMPTS: usize = 5;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_RETRY_BACKOFF: Duration = Duration::from_millis(250);

/// Public status value for a curated Bitcoin endpoint.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Healthy,
    Failed,
    Unknown,
}

impl NodeStatus {
    pub fn as_storage_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_storage_str(value: &str) -> Result<Self, NodeStatusError> {
        match value {
            "healthy" => Ok(Self::Healthy),
            "failed" => Ok(Self::Failed),
            "unknown" => Ok(Self::Unknown),
            other => Err(NodeStatusError::new(format!(
                "unknown node status value: {other}"
            ))),
        }
    }
}

/// Configured target checked by the status runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatusTarget {
    pub endpoint: String,
    pub label: String,
    pub description: String,
}

impl NodeStatusTarget {
    pub fn new(
        endpoint: impl Into<String>,
        label: impl Into<String>,
        description: impl Into<String>,
    ) -> Result<Self, NodeStatusError> {
        let target = Self {
            endpoint: endpoint.into().trim().to_string(),
            label: label.into().trim().to_string(),
            description: description.into().trim().to_string(),
        };
        target.validate()?;
        Ok(target)
    }

    fn validate(&self) -> Result<(), NodeStatusError> {
        if self.endpoint.is_empty() {
            return Err(NodeStatusError::new("status target endpoint is required"));
        }
        if self.label.is_empty() {
            return Err(NodeStatusError::new("status target label is required"));
        }
        if self.description.is_empty() {
            return Err(NodeStatusError::new(
                "status target description is required",
            ));
        }
        Ok(())
    }
}

/// Durable result for one target status check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatusRecord {
    pub endpoint: String,
    pub label: String,
    pub description: String,
    pub status: NodeStatus,
    pub checked_at: DateTime<Utc>,
    pub message: String,
}

impl NodeStatusRecord {
    pub fn from_target(
        target: &NodeStatusTarget,
        status: NodeStatus,
        checked_at: DateTime<Utc>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            endpoint: target.endpoint.clone(),
            label: target.label.clone(),
            description: target.description.clone(),
            status,
            checked_at,
            message: message.into(),
        }
    }
}

/// Compact history point returned by the public status API.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatusHistoryItem {
    pub status: NodeStatus,
    pub checked_at: String,
}

impl From<&NodeStatusRecord> for NodeStatusHistoryItem {
    fn from(value: &NodeStatusRecord) -> Self {
        Self {
            status: value.status,
            checked_at: value.checked_at.to_rfc3339(),
        }
    }
}

/// Latest status row plus bounded history returned by the public status API.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatusItem {
    pub endpoint: String,
    pub label: String,
    pub description: String,
    pub status: NodeStatus,
    pub checked_at: String,
    pub message: String,
    pub history: Vec<NodeStatusHistoryItem>,
}

impl NodeStatusItem {
    pub fn from_latest_and_history(
        latest: NodeStatusRecord,
        history: Vec<NodeStatusRecord>,
    ) -> Self {
        Self {
            endpoint: latest.endpoint,
            label: latest.label,
            description: latest.description,
            status: latest.status,
            checked_at: latest.checked_at.to_rfc3339(),
            message: latest.message,
            history: history
                .iter()
                .map(NodeStatusHistoryItem::from)
                .collect::<Vec<_>>(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeStatusCheckConfig {
    pub attempts: usize,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub retry_backoff: Duration,
}

impl Default for NodeStatusCheckConfig {
    fn default() -> Self {
        Self {
            attempts: DEFAULT_ATTEMPTS,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            io_timeout: DEFAULT_IO_TIMEOUT,
            retry_backoff: DEFAULT_RETRY_BACKOFF,
        }
    }
}

impl NodeStatusCheckConfig {
    pub fn validate(self) -> Result<Self, NodeStatusError> {
        if self.attempts == 0 {
            return Err(NodeStatusError::new(
                "status check attempts must be greater than zero",
            ));
        }
        if self.connect_timeout.is_zero() {
            return Err(NodeStatusError::new(
                "status check connect timeout must be greater than zero",
            ));
        }
        if self.io_timeout.is_zero() {
            return Err(NodeStatusError::new(
                "status check IO timeout must be greater than zero",
            ));
        }
        Ok(self)
    }
}

pub struct NodeStatusChecker {
    config: NodeStatusCheckConfig,
}

impl NodeStatusChecker {
    pub fn new(config: NodeStatusCheckConfig) -> Result<Self, NodeStatusError> {
        Ok(Self {
            config: config.validate()?,
        })
    }

    pub async fn check_target(&self, target: &NodeStatusTarget) -> NodeStatusRecord {
        let mut last_error = "status check did not run".to_string();
        let mut attempts_used = 0usize;

        while attempts_used < self.config.attempts {
            attempts_used += 1;

            match self.try_once(target, attempts_used - 1).await {
                Ok(()) => {
                    return NodeStatusRecord::from_target(
                        target,
                        NodeStatus::Healthy,
                        Utc::now(),
                        "Handshake succeeded.",
                    );
                }
                Err(error) => {
                    last_error = public_error_message(error.as_ref());
                    debug!(
                        endpoint = %target.endpoint,
                        attempt = attempts_used,
                        error = %last_error,
                        "status check attempt failed"
                    );
                    if attempts_used < self.config.attempts {
                        sleep(self.config.retry_backoff).await;
                    }
                }
            }
        }

        NodeStatusRecord::from_target(
            target,
            NodeStatus::Failed,
            Utc::now(),
            format!(
                "Status check failed after {} attempts: {last_error}",
                self.config.attempts
            ),
        )
    }

    async fn try_once(
        &self,
        target: &NodeStatusTarget,
        attempt_index: usize,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let addresses = timeout(self.config.connect_timeout, lookup_host(&target.endpoint))
            .await
            .map_err(|_| {
                format!(
                    "DNS resolution timed out after {:?}",
                    self.config.connect_timeout
                )
            })??
            .collect::<Vec<_>>();

        if addresses.is_empty() {
            return Err("DNS resolution returned no addresses".into());
        }

        let address = addresses[attempt_index % addresses.len()];

        match timeout(
            self.config.connect_timeout,
            AsyncTcpStream::connect(address),
        )
        .await
        {
            Ok(Ok(stream)) => {
                let mut session = AsyncSession::new(stream, self.config.io_timeout);
                session
                    .handshake()
                    .await
                    .map_err(|error| format!("handshake failed: {error}"))?;
                Ok(())
            }
            Ok(Err(error)) => Err(format!("connect failed: {error}").into()),
            Err(_) => {
                Err(format!("connect timed out after {:?}", self.config.connect_timeout).into())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatusError {
    message: String,
}

impl NodeStatusError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for NodeStatusError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for NodeStatusError {}

fn public_error_message(error: &(dyn Error + Send + Sync)) -> String {
    let message = error.to_string();
    if message.len() > 180 {
        format!("{}...", &message[..180])
    } else {
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_requires_endpoint_label_and_description() {
        assert!(NodeStatusTarget::new("", "Seed", "Description").is_err());
        assert!(NodeStatusTarget::new("seed.example:8333", "", "Description").is_err());
        assert!(NodeStatusTarget::new("seed.example:8333", "Seed", "").is_err());
    }

    #[test]
    fn status_round_trips_storage_strings() {
        assert_eq!(
            NodeStatus::from_storage_str("healthy").expect("status"),
            NodeStatus::Healthy
        );
        assert_eq!(NodeStatus::Healthy.as_storage_str(), "healthy");
        assert!(NodeStatus::from_storage_str("up").is_err());
    }

    #[test]
    fn config_rejects_zero_attempts() {
        let config = NodeStatusCheckConfig {
            attempts: 0,
            ..NodeStatusCheckConfig::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn item_uses_latest_row_and_newest_first_history() {
        let target =
            NodeStatusTarget::new("seed.example:8333", "Seed", "Description").expect("target");
        let older = NodeStatusRecord::from_target(
            &target,
            NodeStatus::Failed,
            DateTime::parse_from_rfc3339("2026-05-02T11:59:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            "failed",
        );
        let latest = NodeStatusRecord::from_target(
            &target,
            NodeStatus::Healthy,
            DateTime::parse_from_rfc3339("2026-05-02T12:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            "Handshake succeeded.",
        );

        let item = NodeStatusItem::from_latest_and_history(
            latest.clone(),
            vec![latest.clone(), older.clone()],
        );

        assert_eq!(item.endpoint, "seed.example:8333");
        assert_eq!(item.status, NodeStatus::Healthy);
        assert_eq!(item.checked_at, "2026-05-02T12:00:00+00:00");
        assert_eq!(item.history.len(), 2);
        assert_eq!(item.history[0].status, NodeStatus::Healthy);
        assert_eq!(item.history[1].status, NodeStatus::Failed);
    }
}
