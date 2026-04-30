locals {
  linux_api_cloud_init_source           = "../../../linux/cloud-init/api.yaml"
  linux_api_cloud_init_source_path      = "${path.module}/${local.linux_api_cloud_init_source}"
  linux_api_cloud_init_user_data        = templatefile(local.linux_api_cloud_init_source_path, {})
  linux_postgres_cloud_init_source      = "../../../linux/cloud-init/postgres.yaml"
  linux_postgres_cloud_init_source_path = "${path.module}/${local.linux_postgres_cloud_init_source}"
  linux_postgres_cloud_init_user_data   = templatefile(local.linux_postgres_cloud_init_source_path, {})
}

output "planned_linux_api_cloud_init_source" {
  description = "Repository source used for API/crawler EC2 first-boot cloud-init user data."
  value       = local.linux_api_cloud_init_source
}

output "planned_linux_api_cloud_init_sha256" {
  description = "Content hash for the API/crawler Linux first-boot cloud-init baseline."
  value       = filesha256(local.linux_api_cloud_init_source_path)
}

output "planned_linux_postgres_cloud_init_source" {
  description = "Repository source used for PostgreSQL EC2 first-boot cloud-init user data."
  value       = local.linux_postgres_cloud_init_source
}

output "planned_linux_postgres_cloud_init_sha256" {
  description = "Content hash for the PostgreSQL Linux first-boot cloud-init baseline."
  value       = filesha256(local.linux_postgres_cloud_init_source_path)
}
