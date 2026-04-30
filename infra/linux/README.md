# Linux Host Baseline

Portable Linux host artifacts for the first hosted deployment.

These files are written so the same runtime model can be recreated on any
ordinary Linux servers with minimal adaptation:

- API/crawler host: copy API and crawler environment files to `/etc/btc-network/`
- API/crawler host: copy API/crawler scripts and units to the appropriate paths
- API/crawler host: copy nginx config to the distro-appropriate nginx site directory
- PostgreSQL host: copy PostgreSQL environment files, scripts, units, and config
- PostgreSQL host: adapt PostgreSQL config paths to the distro and PostgreSQL major version

## Layout

- `cloud-init/` - common, API/crawler, and PostgreSQL first-boot provisioning examples
- `env/` - runtime environment-file examples
- `firewall/` - host firewall example commands
- `nginx/` - reverse proxy baseline
- `postgres/` - explicit PostgreSQL config baseline
- `scripts/` - operational shell scripts
- `systemd/` - service and timer units

## Conventions

- API releases: `/opt/btc-network/api/releases/<version>/`
- API active symlink: `/opt/btc-network/api/current`
- Crawler releases: `/opt/btc-network/crawler/releases/<version>/`
- Crawler active symlink: `/opt/btc-network/crawler/current`
- Shared scripts: `/opt/btc-network/bin`
- Config files: `/etc/btc-network`
- Backups: `/var/backups/btc-network/postgres`

## Suggested Install Flow

1. Use `cloud-init/api.yaml` for the API/crawler host and `cloud-init/postgres.yaml` for the PostgreSQL host.
2. Copy example env files from `env/` into `/etc/btc-network/`.
3. Copy scripts from `scripts/` into `/opt/btc-network/bin/` and make them executable.
4. Copy units from `systemd/` into `/etc/systemd/system/`.
5. Copy nginx config from `nginx/` into the distro nginx site path and run `nginx -t`.
6. Copy PostgreSQL config from `postgres/` into the distro PostgreSQL config path.
7. Apply firewall rules from `firewall/`.
8. Run `systemctl daemon-reload` and enable the intended services/timers.

For the AWS production root, Terraform renders `cloud-init/api.yaml` through
`local.linux_api_cloud_init_user_data` and `cloud-init/postgres.yaml` through
`local.linux_postgres_cloud_init_user_data`.

Apply only the artifacts needed by each host role. The API/crawler host should
not receive PostgreSQL server config. The PostgreSQL host should not receive
nginx or API release artifacts.

## Validation

- `nginx -t`
- `systemctl status btc-network-api`
- `systemctl status btc-network-crawler.timer`
- `systemctl status btc-network-postgres-backup.timer`
- `psql -c "select version();"`

Repository helper:

```bash
make infra-linux-check
```

Set `SYSTEMD_VERIFY=1` only on a compatible Linux host where the referenced
systemd runtime paths and commands exist.

## Hosted Operations

The AWS production path uses Systems Manager as the default machine access
channel. From the repository root:

```bash
make infra-aws-ssm-session SSM_INSTANCE_ID=i-...
make infra-aws-api-status API_SSM_INSTANCE_ID=i-...
make infra-aws-postgres-status POSTGRES_SSM_INSTANCE_ID=i-...
make infra-aws-postgres-backup-status POSTGRES_SSM_INSTANCE_ID=i-...
make infra-aws-postgres-backup-run POSTGRES_SSM_INSTANCE_ID=i-...
make infra-aws-crawler-status API_SSM_INSTANCE_ID=i-...
make infra-aws-crawler-timer-status API_SSM_INSTANCE_ID=i-...
make infra-aws-crawler-run API_SSM_INSTANCE_ID=i-...
```

These targets do not replace the files in this directory. They are operator
wrappers around the explicit `systemd` units and scripts that define the host
runtime behavior.

## PostgreSQL 18 Notes

The baseline [postgresql.conf](./postgres/postgresql.conf) now makes these
choices explicit:

- `io_method = worker` as the portable PostgreSQL 18 async-I/O baseline
- `io_workers = 4` with explicit `effective_io_concurrency` settings
- conservative shared-memory settings for a small dedicated PostgreSQL host
- reduced `max_connections` to avoid oversized shared-memory allocation
- less frequent checkpoints through higher `checkpoint_timeout` and
  `max_wal_size`

Do not switch to `io_uring` blindly. Validate all of these first:

- PostgreSQL was built with `liburing` support
- the Linux kernel and runtime support it correctly
- the observed behavior is better than `worker` on the actual storage path
