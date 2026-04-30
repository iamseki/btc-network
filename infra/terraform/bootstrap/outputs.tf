output "state_bucket_name" {
  description = "S3 bucket name for Terraform remote state."
  value       = aws_s3_bucket.terraform_state.bucket
}

output "state_bucket_region" {
  description = "Region for the Terraform state bucket."
  value       = var.aws_region
}

output "backend_lockfile_enabled" {
  description = "Reminder that later roots should use S3 lockfile-based state locking."
  value       = true
}

