# btc-network-mmdb

Local MMDB enrichment adapter for BNDD-0005.

This crate owns:

- filesystem-backed MMDB configuration
- the concrete `IpEnrichmentProvider` implementation
- local ASN, country, and prefix lookups for routable IPv4 and IPv6 endpoints

## Use The Adapter

```rust,no_run
use btc_network_mmdb::{MmdbEnrichmentConfig, MmdbIpEnrichmentProvider};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = MmdbEnrichmentConfig::new(
        "/var/lib/btc-network/GeoLite2-ASN.mmdb",
        "/var/lib/btc-network/GeoLite2-Country.mmdb",
    );

    let provider = MmdbIpEnrichmentProvider::new(config)?;

    Ok(())
}
```

`MmdbIpEnrichmentProvider::new(...)` loads both databases eagerly from disk.

Important:

- the adapter performs local lookups only
- it does not download or refresh MMDB files at runtime
- endpoints that are not enrichment-eligible should stay behind the shared `IpEnrichmentProvider` boundary and resolve to `not_applicable`
- when the adapter is intentionally disabled, use `MmdbIpEnrichmentProvider::unavailable()`

## Verification

From the repository root:

```bash
cargo test -p btc-network-mmdb
git diff --check
```

The crate test suite writes tiny temporary MMDB fixtures at runtime and does not require Docker.
