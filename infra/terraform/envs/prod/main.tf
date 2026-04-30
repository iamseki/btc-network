locals {
  name_prefix = "btc-network-${var.environment}"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

output "planned_stack_name_prefix" {
  description = "Name prefix for production runtime resources."
  value       = local.name_prefix
}

output "planned_api_hostname" {
  description = "Public API hostname this root is expected to manage."
  value       = var.api_hostname
}

output "planned_cloud_account" {
  description = "AWS account where the production runtime root is being planned."
  value       = data.aws_caller_identity.current.account_id
}

