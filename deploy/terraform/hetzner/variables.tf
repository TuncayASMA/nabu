# Hetzner Cloud API token (set via TF_VAR_hcloud_token or tfvars — never hardcode)
variable "hcloud_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

# Instance configuration
variable "server_type" {
  description = "Hetzner server type (CAX11=ARM64 2vCPU/4GB ~€4/mo)"
  type        = string
  default     = "cax11"
}

variable "hcloud_image" {
  description = "Hetzner OS image name"
  type        = string
  default     = "ubuntu-22.04"
}

variable "hcloud_location" {
  description = "Hetzner datacenter location (nbg1=Nuremberg, fsn1=Falkenstein, hel1=Helsinki)"
  type        = string
  default     = "fsn1"
}

# Relay configuration (forwarded to nabu-relay module)
variable "relay_name" {
  description = "Relay instance name"
  type        = string
  default     = "nabu-relay-de"
}

variable "path_id" {
  description = "NABU multipath path ID"
  type        = number
  default     = 1
}

variable "listen_port" {
  description = "NABU relay listen UDP port"
  type        = number
  default     = 7002
}

variable "region_label" {
  description = "Region label for NABU config"
  type        = string
  default     = "de-falkenstein"
}

variable "docker_image" {
  description = "NABU relay Docker image"
  type        = string
  default     = "ghcr.io/TuncayASMA/nabu-relay:latest"
}

variable "ssh_public_key" {
  description = "SSH public key content"
  type        = string
  sensitive   = true
}

variable "nabu_secret" {
  description = "NABU relay pre-shared secret"
  type        = string
  sensitive   = true
}

variable "extra_tags" {
  description = "Additional Hetzner labels"
  type        = map(string)
  default     = {}
}
