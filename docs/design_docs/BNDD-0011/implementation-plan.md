# BNDD-0011 Implementation Plan

Execution plan for [BNDD-0011](./BNDD-0011.md).

## Summary

Stand up the first public API on a single self-managed VM behind Cloudflare, keep PostgreSQL private on the same host, add edge and origin IP-based rate limiting, and leave room to move from OCI bootstrap to a low-cost paid VPS if the zero-dollar path proves unreliable.

## Progress Tracker

Status values:

- `pending`
- `in_progress`
- `reviewing`
- `merged`
- `blocked`

| Phase | Status | Last Updated | Branch or PR | Notes |
| --- | --- | --- | --- | --- |
| Phase 1: Accept provider and edge strategy | `pending` | `2026-04-20` | `n/a` | `Choose OCI bootstrap plus Hetzner fallback, and decide whether to move authoritative DNS to Cloudflare when the API launches.` |
| Phase 2: VM bootstrap and host hardening | `pending` | `2026-04-20` | `n/a` | `Provision one small VM, apply SSH-only access, host firewall rules, system users, packages, and base observability.` |
| Phase 3: Reverse proxy, TLS, and API publish path | `pending` | `2026-04-20` | `n/a` | `Publish api.btcnetwork.info through Cloudflare to a reverse proxy that forwards to the local Rust API service.` |
| Phase 4: PostgreSQL and backup path | `pending` | `2026-04-20` | `n/a` | `Run PostgreSQL locally, bind it privately, add migrations, logical backups, restore checks, and off-host backup copies.` |
| Phase 5: Edge and origin rate limiting | `pending` | `2026-04-20` | `n/a` | `Add Cloudflare IP-based rate limiting for /api/* and a second per-IP origin limit in the reverse proxy.` |
| Phase 6: CI/CD, runbooks, and verification | `pending` | `2026-04-20` | `n/a` | `Automate deploys, document rollback and restore procedures, and verify the production path end to end.` |

## Immediate Next Slice

- decide whether the zero-dollar bootstrap risk from OCI idle reclamation is acceptable
- choose the first reverse proxy implementation and keep rate limiting there
- document the exact API publish hostname and DNS cutover steps
- define the smallest acceptable backup and restore routine before exposing public write volume

## Explicit Agent Constraints

- keep the frontend on Cloudflare Pages unless a later BNDD changes that
- keep PostgreSQL non-public by default
- keep the first deployment to one VM unless there is measured pressure to split it
- do not add Kubernetes, swarm orchestration, or a service mesh in this slice
- keep rate limiting at the edge and origin layers; do not rely on application code alone
- do not let direct-origin access become a supported public path
- prefer simple systemd-managed services over container orchestration unless repository infrastructure direction changes later

## Phases

### Phase 1: Accept Provider And Edge Strategy

Targets:

- `docs/design_docs/BNDD-0011/BNDD-0011.md`
- `docs/deployment.md`
- `docs/agents/architecture-decisions.md` only if accepted deployment defaults change

Done criteria:

- provider strategy is explicitly accepted or revised
- DNS authority decision is explicit
- the repo has one canonical answer for first public API hosting

### Phase 2: VM Bootstrap And Host Hardening

Targets:

- future IaC directory or provisioning scripts
- host bootstrap scripts if adopted
- deployment docs and operator notes

Done criteria:

- one VM can be created repeatably
- SSH keys are required
- password auth is disabled
- firewall defaults are documented and reproducible
- system services have dedicated users and restart policy

### Phase 3: Reverse Proxy, TLS, And API Publish Path

Targets:

- reverse proxy config
- `apps/api` deployment service file or container unit
- DNS and certificate docs

Done criteria:

- `api.btcnetwork.info` resolves through Cloudflare
- the reverse proxy terminates or forwards TLS as designed
- the Rust API listens only on loopback or a private interface
- the public hostname does not require direct client contact with the app process

### Phase 4: PostgreSQL And Backup Path

Targets:

- PostgreSQL config
- migration invocation docs
- backup scripts or timers
- restore runbook

Done criteria:

- PostgreSQL is not reachable on a public interface
- migrations can be applied repeatably
- nightly logical backups run automatically
- restore verification is documented and can be executed
- at least one off-host backup path exists

### Phase 5: Edge And Origin Rate Limiting

Targets:

- Cloudflare zone config
- reverse proxy config
- API operator docs

Done criteria:

- `/api/*` has an edge IP-based rate limit
- origin has a second per-IP limit
- logs identify client IP using trusted Cloudflare headers
- a blocked request path returns a clear `429`

### Phase 6: CI/CD, Runbooks, And Verification

Targets:

- GitHub Actions workflows
- deployment scripts
- `docs/deployment.md`
- troubleshooting or restore runbooks if needed

Done criteria:

- one documented deployment path exists for production
- rollback steps are written down
- database restore steps are written down
- production verification includes health checks and rate-limit checks

## Verification

- `cargo test -p btc-network-api`
- `cargo test -p btc-network-postgres`
- `make test`
- `make security`

Deployment validation after infrastructure exists:

- confirm `api.btcnetwork.info` is reachable only through the intended public edge
- confirm direct PostgreSQL internet access is impossible
- confirm Cloudflare rate limiting blocks or challenges as expected
- confirm origin rate limiting still protects the host when edge limits are intentionally exceeded
- confirm backup artifacts can be restored into a clean PostgreSQL instance
