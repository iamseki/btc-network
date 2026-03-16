# btc-network [![CI](https://github.com/iamseki/btc-network/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/iamseki/btc-network/actions/workflows/ci.yml)

Research-focused Bitcoin P2P implementation in Rust.

The project is organized around clear boundaries between transport, wire decoding, session behavior, and app-facing workflows. It includes Rust binaries, a web-first frontend, and a Tauri desktop shell for exploring protocol behavior.

## Start Here

- [Architecture decisions](docs/architecture-decisions.md)
- [Frontend architecture](docs/frontend-architecture.md)
- [Design docs index](docs/design_docs/README.md)

## Repository Shape

- `crates/btc-network` — shared Rust protocol, session, client, and crawler code
- `apps/cli` — single-peer CLI flows
- `apps/crawler` — network crawler binary
- `apps/listener` — long-running listener binary
- `apps/web` — web-first React frontend
- `apps/desktop` — Tauri desktop shell reusing the web UI

## Current Capabilities

- Bitcoin handshake (`version` / `verack`)
- `addr` / BIP155 `addrv2`
- `getaddr`
- `getheaders`
- iterative tip sync
- block summary
- block download
- desktop-backed UI flows for handshake, ping, addresses, chain height, block summary, and block download
- session log, handshake service-name summaries, and chain-height progress in the current UI

## Development

Build everything:

```bash
make build
```

Run the full test suite:

```bash
make test
```

Useful focused commands:

```bash
cargo test -p btc-network
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml
npm run test --prefix apps/web
npm run build --prefix apps/web
```

## Running

CLI examples:

```bash
make cli ARGS="--node seed.bitnodes.io:8333 ping"
make cli ARGS="--node seed.bitnodes.io:8333 get-addr"
make cli ARGS="--node seed.bitnodes.io:8333 last-block-header"
make cli ARGS="--node seed.bitnodes.io:8333 get-block --hash <block-hash>"
make cli ARGS="--node seed.bitnodes.io:8333 download-block --hash <block-hash>"
```

Crawler:

```bash
make crawler
```

Desktop app:

```bash
make desktop-install
make desktop-dev
```

Web app:

```bash
make web-install
make web-dev
```

## Deploying Web

Phase 1 production deploys use `GitHub Actions` plus `Cloudflare Pages`.

Repository setup:

- create a Cloudflare Pages project for `apps/web`
- add GitHub repository secret `CLOUDFLARE_API_TOKEN`
- add GitHub repository secret `CLOUDFLARE_ACCOUNT_ID`
- add GitHub repository variable `CLOUDFLARE_PAGES_PROJECT_NAME`

The deploy workflow is [deploy-web-pages.yml](/home/chseki/projects/personal/btc-network/.github/workflows/deploy-web-pages.yml). It:

- runs web tests
- builds `apps/web`
- deploys the `dist/` artifact to Cloudflare Pages on pushes to `main`

DNS/domain cutover remains manual for the first phase:

- keep the `btcnetwork.info` registrar at Hostinger
- add `btcnetwork.info` as a custom domain in Cloudflare Pages
- update the required DNS records in Hostinger to point the domain at Cloudflare Pages
- reserve `api.btcnetwork.info` for the future API

This keeps the CI/CD path automated without making Phase 1 depend on Hostinger DNS automation.

Manual setup steps:

1. In Cloudflare, create or open the Pages project named in `CLOUDFLARE_PAGES_PROJECT_NAME`.
2. In the Pages project, open `Custom domains`.
3. Add `btcnetwork.info` as the production custom domain.
4. Copy the DNS target values Cloudflare Pages shows for the apex domain and, if prompted, the `www` hostname.
5. In Hostinger hPanel, open the DNS zone for `btcnetwork.info`.
6. Remove or update any existing `@` or `www` records that would conflict with the Pages records.
7. Create the exact DNS records Cloudflare Pages requested in Hostinger.
8. Save the Hostinger DNS changes and wait for propagation.
9. Return to Cloudflare Pages and confirm the custom domain becomes active and HTTPS is issued.
10. Keep `api.btcnetwork.info` unused for now so it remains available for the future API cutover.

Practical notes:

- Use the DNS values shown inside Cloudflare Pages as the source of truth instead of hardcoding record values in repo docs.
- If Hostinger already has a parking page or default records for `@` or `www`, remove those before adding the Pages records.
- If you want `www.btcnetwork.info` to work, add it as an extra custom domain in Pages and mirror the DNS records Pages asks for.

## Notes

- The root `Cargo.toml` is a virtual workspace manifest.
- The root `Cargo.lock` is authoritative for the Rust workspace.
- The plain web runtime still uses placeholder-backed flows where a browser-safe backend does not exist yet.
- Desktop builds on Ubuntu/Debian require system packages documented in `apps/desktop/README.md`.

## License

Licensed under Apache-2.0. See [LICENSE](LICENSE).
