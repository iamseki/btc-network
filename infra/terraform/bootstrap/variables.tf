variable "aws_region" {
  description = "AWS region for the Terraform state bucket."
  type        = string
}

variable "state_bucket_name" {
  description = "Globally unique S3 bucket name for Terraform state."
  type        = string
}

variable "noncurrent_days" {
  description = "Days to retain noncurrent Terraform state versions."
  type        = number
  default     = 7
}

variable "newer_noncurrent_versions" {
  description = "Maximum number of newer noncurrent state versions to retain."
  type        = number
  default     = 2
}

variable "tags" {
  description = "Common resource tags."
  type        = map(string)
  default     = {}
}

