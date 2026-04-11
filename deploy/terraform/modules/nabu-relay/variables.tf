variable "relay_name" {
  description = "Unique name for this relay instance (e.g. nabu-relay-fr, nabu-relay-de)"
  type        = string
}

variable "path_id" {
  description = "NABU multipath path ID assigned to this relay (0-based)"
  type        = number
}

variable "listen_port" {
  description = "UDP port the relay listens on for NABU traffic"
  type        = number
  default     = 7000
}

variable "probe_port_offset" {
  description = "Probe port = listen_port + probe_port_offset (default 1000)"
  type        = number
  default     = 1000
}

variable "docker_image" {
  description = "NABU relay Docker image (e.g. ghcr.io/TuncayASMA/nabu-relay:latest)"
  type        = string
  default     = "ghcr.io/TuncayASMA/nabu-relay:latest"
}

variable "region_label" {
  description = "Human-readable region label (e.g. fr-marseille, de-falkenstein)"
  type        = string
}

variable "ssh_public_key" {
  description = "SSH public key content for remote access"
  type        = string
  sensitive   = true
}

variable "nabu_secret" {
  description = "Pre-shared secret used for NABU relay authentication"
  type        = string
  sensitive   = true
}

variable "extra_tags" {
  description = "Additional key-value tags to apply to cloud resources"
  type        = map(string)
  default     = {}
}
