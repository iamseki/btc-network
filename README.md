# btc-network [![CI](https://github.com/iamseki/btc-network/actions/workflows/cicd.yml/badge.svg?branch=main)](https://github.com/iamseki/btc-network/actions/workflows/cicd.yml)  [![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-Support-FFDD00?logo=buymeacoffee&logoColor=000000)](https://buymeacoffee.com/chseki)

btc-network is a Rust-based Bitcoin P2P research and observability project focused on peer discovery, protocol behavior, and network analytics. It combines low-level wire protocol and session handling with crawler infrastructure, PostgreSQL-backed analytics, and web and desktop interfaces for exploring network state and behavior.

## Start Here

- [Docs index](docs/README.md)
- [Contributing guide](CONTRIBUTING.md)
- [Deployment guide](docs/deployment.md)
- [Design docs index](docs/design_docs/README.md)
- [Agent guidance](AGENTS.md)

## Repository Shape

- `crates/btc-network` — shared Rust protocol, session, client, and crawler code
- `apps/api` — browser-safe HTTP API for crawler analytics reads
- `apps/cli` — single-peer CLI flows
- `apps/crawler` — network crawler binary
- `apps/postgres-migrate` — PostgreSQL migration runner for local and container flows
- `apps/web` — web-first React frontend
- `apps/desktop` — Tauri desktop shell reusing the web UI
- `infra/` — Terraform and portable Linux host scaffolding for hosted deployment

## Current Capabilities

- read-only crawler analytics API for runs, run detail, and top ASN counts
- web analytics surfaces for crawler runs, network analytics, and commercial API previews
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

List the repository helper commands:

```bash
make help
```

Optional local git hook setup:

```bash
make setup-git-hooks
```

This repository includes a repo-local `commit-msg` hook under `.githooks/` that validates semantic commit subjects such as `feat(crawler): ...` or `docs: ...`. The hook is opt-in per clone. `make setup-git-hooks` configures `core.hooksPath=.githooks` for the current clone. CI enforces pull request titles with the same semantic pattern, while commit-subject validation remains a local convention unless you enable the hook.

## Running

CLI examples:

```bash
make cli ARGS="--node seed.bitnodes.io:8333 ping"
make cli ARGS="--node seed.bitnodes.io:8333 get-addr"
make cli ARGS="--node seed.bitnodes.io:8333 last-block-header"
make cli ARGS="--node seed.bitnodes.io:8333 get-block --hash <block-hash>"
make cli ARGS="--node seed.bitnodes.io:8333 download-block --hash <block-hash>"
```

Crawler with docker:

```bash
make infra-crawler-up
```

API:

```bash
make api
```

For the preferred local crawler setup with the shared Docker-backed PostgreSQL service and local MMDB files, see [apps/crawler/README.md](apps/crawler/README.md).
That guide also documents how to fetch and refresh the local MMDB datasets used by the crawler.

Docker Compose profiles:

```bash
docker compose up postgres
docker compose --profile crawler up
docker compose --profile crawler --profile api up
```

`postgres` is the shared unprofiled service. Enabling the `crawler` or `api`
profiles also runs the one-shot `postgres-migrate` service before the app
containers start.

Equivalent `make` wrappers:

```bash
make infra-postgres-up
make infra-postgres-down
make infra-postgres-reset
make infra-crawler-up
make infra-api-up
make infra-crawler-api-up
make infra-compose-down
make infra-compose-reset
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
make web-dev-demo
```

## Deploying Web

Phase 1 production deploys use the repository `CI/CD` GitHub Actions workflow plus `Cloudflare Pages`.

See [docs/deployment.md](docs/deployment.md) for the current production setup, required GitHub and Cloudflare configuration, and the manual Hostinger DNS steps.

Hosted backend scaffolding for BNDD-0011 lives under [infra/](infra/README.md).

## Notes

- The root `Cargo.toml` is a virtual workspace manifest.
- The root `Cargo.lock` is authoritative for the Rust workspace.
- The web app uses `apps/api` for browser-safe crawler analytics reads and still uses placeholder-backed flows where a browser-safe backend does not exist yet.
- Desktop builds on Ubuntu/Debian require system packages documented in `apps/desktop/README.md`.

## License

Licensed under Apache-2.0. See [LICENSE](LICENSE).
