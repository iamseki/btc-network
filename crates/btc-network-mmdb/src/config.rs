use std::path::{Path, PathBuf};

/// Filesystem paths for the local MMDB datasets used by the crawler enricher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmdbEnrichmentConfig {
    asn_db_path: PathBuf,
    country_db_path: PathBuf,
}

impl MmdbEnrichmentConfig {
    /// Builds a config that points to the ASN and country MMDB datasets.
    pub fn new(asn_db_path: impl Into<PathBuf>, country_db_path: impl Into<PathBuf>) -> Self {
        Self {
            asn_db_path: asn_db_path.into(),
            country_db_path: country_db_path.into(),
        }
    }

    /// Returns the local ASN MMDB path.
    pub fn asn_db_path(&self) -> &Path {
        &self.asn_db_path
    }

    /// Returns the local country MMDB path.
    pub fn country_db_path(&self) -> &Path {
        &self.country_db_path
    }
}
