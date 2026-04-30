# Production Runtime Root

Production runtime scaffold for the first hosted deployment.

This root is intentionally explicit about the infrastructure shape even before
all resources are fully materialized.

## Planned Resource Inventory

AWS:

- one VPC
- one public subnet
- one private application subnet for PostgreSQL
- one internet gateway
- one public route table and association
- one private route strategy for Systems Manager and backup access from the
  PostgreSQL host
- one security group for the public API/crawler host
- one security group for the private PostgreSQL host, allowing `5432` only from
  the API/crawler security group
- one IAM role and instance profile for API deploy and SSM operations
- one IAM role and instance profile for PostgreSQL SSM, backup, and snapshot
  operations
- one EC2 instance for reverse proxy, API, and crawler triggers
- one private EC2 instance for PostgreSQL
- one EBS volume or root-volume sizing policy appropriate for PostgreSQL growth
- one Elastic IP for stable origin addressing

Cloudflare:

- one proxied `api.btcnetwork.info` DNS record
- cache rules for safe anonymous public `GET` endpoints
- rate limiting rules for `/api/*`

Linux host runtime:

- API/crawler host: nginx reverse proxy
- API/crawler host: `btc-network-api` systemd unit
- API/crawler host: `btc-network-crawler` oneshot systemd unit and optional timer
- PostgreSQL host: PostgreSQL config baseline
- PostgreSQL host: PostgreSQL backup service and timer
- both hosts: environment files under `/etc/btc-network`

## Backend

This root expects the bootstrap state bucket to exist first.

Example:

```bash
cd infra/terraform/envs/prod
terraform init \
  -backend-config="bucket=btc-network-tf-state-example" \
  -backend-config="key=envs/prod/terraform.tfstate" \
  -backend-config="region=us-east-1" \
  -backend-config="use_lockfile=true"
```

Equivalent repository helper:

```bash
make infra-tf-prod-init TF_STATE_BUCKET=btc-network-tf-state-example
```

After initialization:

```bash
make infra-tf-prod-validate
make infra-tf-prod-plan
```

Apply is intentionally guarded:

```bash
make infra-tf-prod-apply CONFIRM_APPLY=1
```

## Notes

- This root is scaffolded first as a clear inventory and provider shell.
- Add concrete resources incrementally instead of dropping a large unreviewed
  stack at once.
- Keep AWS-specific resources here and Linux host artifacts under `infra/linux`.

## Linux Host Bootstrap

This root links to the portable Linux baselines through:

- `local.linux_api_cloud_init_user_data`, rendered from
  `../../../linux/cloud-init/api.yaml`
- `local.linux_postgres_cloud_init_user_data`, rendered from
  `../../../linux/cloud-init/postgres.yaml`

When the EC2 resources are added, pass those locals into the matching first-boot
paths:

```hcl
resource "aws_instance" "api" {
  # ...
  user_data = local.linux_api_cloud_init_user_data
}

resource "aws_instance" "postgres" {
  # ...
  user_data = local.linux_postgres_cloud_init_user_data
}
```

Treat this as first-boot bootstrap only. Ongoing service changes should stay in
the explicit host artifacts under `infra/linux` and be applied through the
release or operator workflow, not hidden inside Terraform provisioner scripts.

## Deployment Role Organization

Keep Terraform focused on AWS and Cloudflare resources. Keep routine API and
PostgreSQL deployment ownership in the role docs under `infra/deployments/`:

- `infra/deployments/api/`
- `infra/deployments/postgres/`
