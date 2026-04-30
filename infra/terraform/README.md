# Terraform

Terraform roots for infrastructure described by BNDD-0011.

Current roots:

- `bootstrap/` - creates the remote state bucket
- `envs/prod/` - production runtime root scaffold and resource inventory

Terraform defines cloud resources only. Role-specific API and PostgreSQL
deployment ownership lives under `infra/deployments/`.

## Workflow

1. Apply `bootstrap/` once with local state.
2. Use the created S3 bucket as the backend for `envs/prod/`.
3. Keep short noncurrent retention on the state bucket.
4. Run `terraform plan` in CI for review before apply.

Repository Make targets wrap the common local/operator flow:

- `make infra-tf-fmt-check`
- `make infra-tf-bootstrap-init`
- `make infra-tf-bootstrap-plan`
- `make infra-tf-bootstrap-apply CONFIRM_APPLY=1`
- `make infra-tf-prod-init TF_STATE_BUCKET=...`
- `make infra-tf-prod-validate`
- `make infra-tf-prod-plan`
- `make infra-tf-prod-apply CONFIRM_APPLY=1`

Use `TERRAFORM=tofu` when validating OpenTofu compatibility locally.

## Notes

- The state bucket is intentionally versioned but not a long-term audit archive.
- Noncurrent state versions should expire quickly.
- Runtime resources stay in a separate root from the bootstrap state bucket.
- Apply targets are guarded so plans remain a deliberate review step before
  remote-state changes.
