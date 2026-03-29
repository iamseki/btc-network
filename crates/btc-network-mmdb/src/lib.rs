#![doc = include_str!("../README.md")]

mod config;
mod provider;

pub use config::MmdbEnrichmentConfig;
pub use provider::{MmdbEnrichmentInitError, MmdbIpEnrichmentProvider};
