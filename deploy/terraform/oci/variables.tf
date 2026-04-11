# OCI provider authentication
variable "tenancy_ocid" {
  description = "OCI tenancy OCID"
  type        = string
  sensitive   = true
}

variable "user_ocid" {
  description = "OCI user OCID"
  type        = string
  sensitive   = true
}

variable "fingerprint" {
  description = "OCI API key fingerprint"
  type        = string
  sensitive   = true
}

variable "private_key_path" {
  description = "Path to OCI API private key PEM file"
  type        = string
  default     = "~/.oci/oci_api_key.pem"
}

variable "compartment_ocid" {
  description = "OCI compartment OCID where resources will be created"
  type        = string
  sensitive   = true
}

variable "oci_region" {
  description = "OCI region identifier (e.g. eu-marseille-1, uk-london-1)"
  type        = string
  default     = "eu-marseille-1"
}

variable "availability_domain" {
  description = "OCI availability domain within the region"
  type        = string
  default     = "Gwul:EU-MARSEILLE-1-AD-1"
}

variable "oci_image_id" {
  description = "OCI image OCID — Ubuntu 22.04 ARM64 (region-specific)"
  type        = string
  # Default: Ubuntu 22.04 Minimal ARM64 in eu-marseille-1
  # Update per region: https://docs.oracle.com/iaas/images/
  default     = "ocid1.image.oc1.eu-marseille-1.aaaaaaaaukv7dwvywwm5h6tltqdv7pnm7t5kxc5x5tzb3sjomvpw6pwrv3rq"
}

# Relay configuration (forwarded to nabu-relay module)
variable "relay_name" {
  description = "Relay instance name"
  type        = string
  default     = "nabu-relay-fr"
}

variable "path_id" {
  description = "NABU multipath path ID"
  type        = number
  default     = 0
}

variable "listen_port" {
  description = "NABU relay listen UDP port"
  type        = number
  default     = 7001
}

variable "region_label" {
  description = "Region label for NABU config"
  type        = string
  default     = "fr-marseille"
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
  description = "Additional freeform tags"
  type        = map(string)
  default     = {}
}
