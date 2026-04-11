output "user_data" {
  description = "cloud-init bootstrap script for the relay instance"
  value       = local.user_data
  sensitive   = true
}

output "nabu_config_snippet" {
  description = "TOML snippet for the client's nabu.toml [[relays]] section"
  value       = local.nabu_config_snippet
}

output "relay_public_ip" {
  description = "Public IPv4 address of the relay instance"
  value       = var.public_ip
}

output "relay_name" {
  description = "Relay instance name"
  value       = var.relay_name
}

output "path_id" {
  description = "NABU multipath path ID"
  value       = var.path_id
}

output "listen_port" {
  description = "NABU relay listen port"
  value       = var.listen_port
}

output "probe_port" {
  description = "UDP echo probe port (listen_port + probe_port_offset)"
  value       = var.listen_port + var.probe_port_offset
}

output "nabu_endpoint" {
  description = "Full relay endpoint address (host:port) for MultiPathConn"
  value       = var.public_ip != "" ? "${var.public_ip}:${var.listen_port}" : "<PENDING>:${var.listen_port}"
}
