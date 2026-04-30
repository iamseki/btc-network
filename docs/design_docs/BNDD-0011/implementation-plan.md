# BNDD-0011 Implementation Plan

Execution plan for [BNDD-0011](./BNDD-0011.md).

## Summary

Stand up the first public API on one AWS API/crawler EC2 VM behind Cloudflare and one private AWS PostgreSQL EC2 VM, use Terraform for reviewable infrastructure changes, run the crawler as a non-overlapping batch workload on the API/crawler host, and keep a clear path toward future edge caching before any API fleet or managed database move.

## Progress Tracker

Status values:

- `pending`
- `in_progress`
- `reviewing`
- `merged`
- `blocked`

| Phase | Status | Last Updated | Branch or PR | Notes |
| --- | --- | --- | --- | --- |
| Phase 1: Accept provider, IaC, and edge strategy | `in_progress` | `2026-04-25` | `n/a` | `BNDD revised to AWS + Terraform + Cloudflare edge. Initial infra tree and Make operator targets are being added.` |
| Phase 2: Bootstrap Terraform state and AWS network baseline | `pending` | `2026-04-25` | `n/a` | `Create remote state with intentionally short noncurrent retention, plus VPC, public API subnet, private PostgreSQL subnet, route tables, security groups, IAM roles, and Make wrappers for repeatable plan/apply commands.` |
| Phase 3: VM bootstrap and host operations baseline | `pending` | `2026-04-25` | `n/a` | `Apply role-specific cloud-init, SSM access, Patch Manager, CloudWatch alarms, service users, base packages, Linux artifact checks, and reproducible API/PostgreSQL host inventories.` |
| Phase 4: Reverse proxy, API publish path, and DNS cutover | `pending` | `2026-04-23` | `n/a` | `Publish api.btcnetwork.info through Cloudflare to the EC2 reverse proxy and remove direct-origin expectations.` |
| Phase 5: PostgreSQL, migrations, and backup path | `pending` | `2026-04-25` | `n/a` | `Run PostgreSQL on the private database host, automate migrations, logical backups, EBS snapshots, restore checks, and documented Make/SSM backup operation commands.` |
| Phase 6: Crawler scheduling and trigger path | `pending` | `2026-04-25` | `n/a` | `Run the crawler as a oneshot service on the API/crawler host with timer and manual trigger paths, block overlapping runs, and expose documented Make/SSM trigger/status commands.` |
| Phase 7: CI/CD and infrastructure diff workflow | `pending` | `2026-04-25` | `n/a` | `Add Terraform plan/apply workflows, Make command documentation, and separate API/PostgreSQL deployment workflows with controlled host updates.` |
| Phase 8: Future cache and scale triggers | `pending` | `2026-04-25` | `n/a` | `Document cache headers, purge path, and the metrics that trigger API fleet, crawler host, managed database, or larger PostgreSQL host changes.` |

## Immediate Next Slice

- decide the first AWS region and API/PostgreSQL instance families after checking the AWS credit window and expected storage profile
- define the first Terraform root layout for bootstrap state, Cloudflare, AWS network, API host, PostgreSQL host, and SSM/private management endpoints
- choose the reverse proxy implementation and standardize the trusted-proxy/header handling
- define the minimal migration, backup, and restore flow before exposing the public API
- define the first Linux page-cache, reclaim, and memory baseline for the dedicated PostgreSQL host
- decide whether the first crawler trigger should live in a host-local systemd timer, SSM-driven manual runs, or both
- define whether the first API deploy path accepts brief downtime or includes same-host blue/green cutover immediately
- define the first cache rule set for safe public read endpoints on the Cloudflare free plan
- define the concrete Linux host artifact inventory, including PostgreSQL config files and systemd units
- keep `make help` as the documented local/operator entrypoint for Terraform, host checks, SSM access, and database service operations

## Explicit Agent Constraints

- keep the frontend on Cloudflare Pages unless a later BNDD changes that
- keep the first backend topology to one API/crawler EC2 instance and one private PostgreSQL EC2 instance unless measured pressure justifies another split
- keep PostgreSQL non-public by default
- keep Terraform HCL as the canonical infrastructure format and preserve OpenTofu compatibility where practical
- prefer AWS Systems Manager for admin access over broad public SSH exposure
- keep PostgreSQL host access private; prefer SSM VPC endpoints over public SSH or public database access
- keep rate limiting at both the Cloudflare edge and origin reverse proxy layers
- keep the single-active-crawler model explicit as a design choice unless a later design explicitly changes that rule
- keep Cloudflare caching limited to explicitly safe public read endpoints
- prefer systemd-managed services over container orchestration in this slice
- do not add Kubernetes, ECS, or managed PostgreSQL in this slice
- keep Make targets thin; move complex reusable host logic into scripts instead of embedding long shell workflows in the Makefile

## Phases

### Phase 1: Accept Provider, IaC, And Edge Strategy

Targets:

- `docs/design_docs/BNDD-0011/BNDD-0011.md`
- `docs/deployment.md`
- `docs/agents/architecture-decisions.md`
- adjacent BNDD docs only where future-hosting defaults would otherwise be stale

Done criteria:

- AWS-first provider direction is explicit
- Terraform workflow and remote-state stance are explicit
- Cloudflare edge and DNS cutover stance are explicit
- the repository has one canonical answer for first public API hosting

### Phase 2: Bootstrap Terraform State And AWS Network Baseline

Targets:

- future `infra/` or equivalent Terraform roots
- bootstrap documentation for remote state
- AWS network and IAM docs if needed
- repository Make targets for repeatable Terraform init, validate, plan, and guarded apply commands

Done criteria:

- remote Terraform state exists and is documented
- remote state retention is intentionally short and documented
- one VPC, public API subnet, private PostgreSQL subnet, route tables, and security groups can be created repeatably
- API and PostgreSQL EC2 instance roles are scoped separately for SSM, deploy, and backup operations
- the PostgreSQL host has a private management path through SSM endpoints or another documented private egress path
- infrastructure diff and apply boundaries are documented
- `make help` exposes the supported Terraform commands and required variables

### Phase 3: VM Bootstrap And Host Operations Baseline

Targets:

- host bootstrap scripts or cloud-init templates
- systemd units
- package and filesystem layout docs
- operator docs
- Make target for local Linux artifact syntax checks
- Make targets for AWS Systems Manager session and command dispatch

Done criteria:

- both VM roles can be bootstrapped repeatably
- Session Manager access works
- patching policy is defined
- service users and restart policy are defined
- the repo documents the concrete Linux host artifacts to reproduce API and PostgreSQL roles on another server
- basic alarms and recovery actions are documented
- common host status checks are reachable through documented Make/SSM commands

### Phase 4: Reverse Proxy, API Publish Path, And DNS Cutover

Targets:

- reverse proxy config
- `apps/api` deployment service file or artifact layout
- DNS and certificate docs

Done criteria:

- `api.btcnetwork.info` resolves through Cloudflare
- the reverse proxy forwards only to the local Rust API service
- the Rust API listens only on loopback or another private local interface
- the origin IP is not treated as a supported public endpoint

### Phase 5: PostgreSQL, Migrations, And Backup Path

Targets:

- PostgreSQL config, including `postgresql.conf` and `pg_hba.conf`
- host memory and reclaim config, such as `sysctl.d` and `systemd` resource controls where needed
- migration invocation docs or workflow
- backup scripts or timers
- restore runbook
- Make targets for hosted PostgreSQL status and manual backup trigger through Systems Manager

Done criteria:

- PostgreSQL is not reachable on a public interface
- the PostgreSQL config baseline is explicit and reproducible on a plain Linux host
- the database host memory budget explicitly accounts for PostgreSQL plus Linux page cache, and reclaim or eviction posture is documented
- migrations can be applied repeatably
- logical backups run automatically
- EBS snapshot lifecycle is automated
- restore verification is documented and executable
- database operation commands are discoverable through `make help`

### Phase 6: Crawler Scheduling And Trigger Path

Targets:

- crawler systemd unit and timer definitions if adopted
- SSM-trigger documentation or scripts if adopted
- operator notes for overlapping-run prevention
- Make targets for hosted crawler status, timer status, and manual trigger through Systems Manager

Done criteria:

- the crawler can run as a oneshot batch process on the API/crawler EC2 host
- at least one recurring or manual trigger path is documented and reproducible
- a second trigger cannot start a concurrent crawler run against the same database
- the docs explain that the single-active-crawler rule is intentional and tied to process-local concurrency control
- logs make skipped or blocked duplicate triggers explicit
- crawler operation commands are discoverable through `make help`

### Phase 7: CI/CD And Infrastructure Diff Workflow

Targets:

- GitHub Actions workflows
- deployment scripts
- Terraform plan output handling
- `docs/deployment.md`
- Make command documentation for local and CI Terraform workflows
- separate API and PostgreSQL deployment documentation

Done criteria:

- PRs produce reviewable Terraform diffs
- mainline or protected deploys can apply infrastructure safely
- API deployments are versioned and repeatable
- PostgreSQL config, backup, and migration deployments are versioned and repeatable separately from API binary rollouts
- the deploy path documents whether it uses brief-restart rollout or same-host blue/green
- rollback steps are written down

### Phase 8: Future Cache And Scale Triggers

Targets:

- API caching docs
- cache invalidation helpers if adopted
- operator notes for scale triggers

Done criteria:

- cacheable API endpoints and headers are identified
- Cloudflare free-plan cache rules for those endpoints are documented or implemented
- targeted cache invalidation path is documented
- API fleet, crawler host, database resize, managed database, and cache scale triggers are written down
- future edge-compute work is explicitly deferred unless a new need appears

## Verification

- `cargo test -p btc-network-api`
- `cargo test -p btc-network-postgres`
- `make test`
- `make security`

Deployment validation after infrastructure exists:

- confirm `api.btcnetwork.info` is reachable only through the intended public edge
- confirm direct PostgreSQL internet access is impossible
- confirm Terraform plan output is available for infra changes before apply
- confirm the API deploy workflow can update the host without manual snowflake steps
- confirm backups can be restored into a clean PostgreSQL instance
- confirm cache invalidation design is documented before enabling public edge caching
