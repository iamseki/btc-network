variable "aws_region" {
  description = "AWS region for the production stack."
  type        = string
}

variable "environment" {
  description = "Short environment name."
  type        = string
  default     = "prod"
}

variable "domain_name" {
  description = "Primary DNS zone, for example btcnetwork.info."
  type        = string
}

variable "api_hostname" {
  description = "Public API hostname."
  type        = string
  default     = "api.btcnetwork.info"
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone id for the public domain."
  type        = string
}

variable "tags" {
  description = "Common resource tags."
  type        = map(string)
  default     = {}
}

