# Infrastructure

Scaffold for the hosted infrastructure and Linux host artifacts described by
[BNDD-0011](../docs/design_docs/BNDD-0011/BNDD-0011.md).

This tree has two goals:

- keep cloud resources reproducible through Terraform-style configuration
- keep host-level runtime behavior reproducible on any ordinary Linux server
- keep API and PostgreSQL deployment responsibilities separate now that those
  roles run on separate hosts

The repository is AWS-first today, but the Linux service model is intentionally
portable:

- reverse proxy
- systemd-managed API and crawler services
- explicit PostgreSQL config
- explicit backup scripts
- explicit environment files

## Layout

- `terraform/` - cloud resources, state bootstrap, and environment roots
- `linux/` - portable Linux host artifacts such as `cloud-init`, `systemd`,
  PostgreSQL, nginx, firewall, and backup scripts
- `deployments/` - role-oriented operator notes for API/crawler and PostgreSQL
  deployment ownership

## Principles

- prefer explicit files over undocumented shell history
- keep production-relevant behavior mapped to a concrete file, unit, rule, or
  command
- keep AWS-specific pieces isolated from Linux host runtime artifacts
- keep API deployment and PostgreSQL deployment separate unless a change truly
  spans both roles
- keep defaults conservative and easy to reason about

## Operator Entry Point

Use `make help` from the repository root to discover supported infrastructure
commands.

Common hosted-infrastructure groups:

- `infra-tf-*` - Terraform formatting, init, validate, plan, and guarded apply
- `infra-linux-check` - local syntax checks for portable Linux host artifacts
- `infra-aws-*` - AWS Systems Manager session, command dispatch, and common
  service operations

Apply targets require `CONFIRM_APPLY=1`. AWS Systems Manager targets use
role-specific instance variables such as `API_SSM_INSTANCE_ID=...` and
`POSTGRES_SSM_INSTANCE_ID=...`, with `AWS_REGION` when set.
