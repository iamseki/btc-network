# PostgreSQL Deployment

Deployment ownership for the private PostgreSQL host.

This role owns:

- PostgreSQL package/config baseline
- PostgreSQL host memory and writeback tuning
- `postgresql.conf`
- `pg_hba.conf`
- migration execution policy
- logical backup script and timer
- EBS snapshot policy
- restore checks

This role does not own:

- public reverse proxy config
- Rust API release artifact
- crawler trigger cadence, except where database lock behavior must be respected

## Operator Commands

```bash
make infra-aws-postgres-status POSTGRES_SSM_INSTANCE_ID=i-...
make infra-aws-postgres-backup-status POSTGRES_SSM_INSTANCE_ID=i-...
make infra-aws-postgres-backup-run POSTGRES_SSM_INSTANCE_ID=i-...
```

## Network Stance

The PostgreSQL host should have no supported public client endpoint. Allow
`5432` only from the API/crawler security group over the private network, and
keep host access through Systems Manager or another documented private
management path.
