# Hosted Deployment Roles

Role-oriented deployment notes for the split hosted infrastructure.

Terraform owns the AWS and Cloudflare resources. The files here describe how
application and database changes should be grouped after those resources exist.

## Roles

- `api/` - Rust API artifact, reverse proxy changes, API environment references,
  and API systemd rollout on the public API/crawler host
- `postgres/` - PostgreSQL config, host tuning, migrations, logical backups,
  snapshot policy, and restore checks on the private database host

## Rules

- keep API binary rollouts separate from PostgreSQL config and backup changes
- keep database migrations explicit and reviewable before public API deployment
  depends on them
- keep PostgreSQL host operations behind Systems Manager or another documented
  private management path
- do not use Terraform provisioners for routine API or PostgreSQL deployment
  steps
- keep reusable host logic in `infra/linux/scripts/` or `scripts/`, not inline
  in the Makefile

## Operator Entry Points

From the repository root:

```bash
make infra-aws-api-status API_SSM_INSTANCE_ID=i-...
make infra-aws-postgres-status POSTGRES_SSM_INSTANCE_ID=i-...
make infra-aws-postgres-backup-status POSTGRES_SSM_INSTANCE_ID=i-...
make infra-aws-postgres-backup-run POSTGRES_SSM_INSTANCE_ID=i-...
make infra-aws-crawler-status API_SSM_INSTANCE_ID=i-...
make infra-aws-crawler-run API_SSM_INSTANCE_ID=i-...
```

