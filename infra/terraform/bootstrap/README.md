# Bootstrap State Bucket

This root creates the S3 bucket used by other Terraform roots for remote state.

It intentionally keeps a short rollback window:

- bucket versioning enabled
- noncurrent versions retained only briefly
- public access blocked
- server-side encryption enabled

## Apply Order

```bash
cd infra/terraform/bootstrap
terraform init
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

After apply, use the created bucket name in the runtime root backend config.

## Files

- `main.tf` - state bucket resources
- `variables.tf` - input variables
- `outputs.tf` - backend values to copy into later roots
- `terraform.tfvars.example` - example values

