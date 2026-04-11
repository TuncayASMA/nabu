output "relay_public_ip" {
  description = "Public IPv4 of the OCI relay instance"
  value       = oci_core_instance.relay.public_ip
}

output "relay_name" {
  description = "OCI instance display name"
  value       = oci_core_instance.relay.display_name
}

output "nabu_endpoint" {
  description = "NABU relay endpoint (host:port)"
  value       = module.relay_cfg.nabu_endpoint
}

output "probe_port" {
  description = "UDP echo probe port"
  value       = module.relay_cfg.probe_port
}

output "nabu_config_snippet" {
  description = "TOML config snippet for client nabu.toml"
  value       = module.relay_cfg.nabu_config_snippet
}

output "path_id" {
  description = "NABU multipath path ID"
  value       = module.relay_cfg.path_id
}
