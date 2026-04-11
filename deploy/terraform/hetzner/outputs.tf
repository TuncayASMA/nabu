output "relay_public_ip" {
  description = "Public IPv4 of the Hetzner relay server"
  value       = hcloud_server.relay.ipv4_address
}

output "relay_name" {
  description = "Hetzner server name"
  value       = hcloud_server.relay.name
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
