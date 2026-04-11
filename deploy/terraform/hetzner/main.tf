##############################################################################
# Hetzner Cloud — NABU relay instance
# ARM64 CAX11 (2 vCPU / 4 GB RAM — ~€4/mo in Falkenstein)
#
# Authentication via HCLOUD_TOKEN environment variable (never hardcoded).
# Required:
#   export HCLOUD_TOKEN=<your_hetzner_api_token>
##############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }
}

provider "hcloud" {
  token = var.hcloud_token
}

# ---------------------------------------------------------------------------
# nabu-relay module (config generator)
# ---------------------------------------------------------------------------
module "relay_cfg" {
  source = "../modules/nabu-relay"

  relay_name     = var.relay_name
  path_id        = var.path_id
  listen_port    = var.listen_port
  region_label   = var.region_label
  docker_image   = var.docker_image
  ssh_public_key = var.ssh_public_key
  nabu_secret    = var.nabu_secret
  extra_tags     = var.extra_tags

  # public_ip resolved after instance creation
  public_ip = hcloud_server.relay.ipv4_address
}

# ---------------------------------------------------------------------------
# SSH key
# ---------------------------------------------------------------------------
resource "hcloud_ssh_key" "nabu" {
  name       = "${var.relay_name}-key"
  public_key = var.ssh_public_key

  labels = merge({ "project" = "nabu" }, var.extra_tags)
}

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
resource "hcloud_firewall" "nabu" {
  name = "${var.relay_name}-fw"

  # SSH
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "22"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # NABU relay UDP
  rule {
    direction = "in"
    protocol  = "udp"
    port      = tostring(var.listen_port)
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # NABU probe echo UDP (listen_port + 1000)
  rule {
    direction = "in"
    protocol  = "udp"
    port      = tostring(var.listen_port + 1000)
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  labels = merge({ "project" = "nabu" }, var.extra_tags)
}

# ---------------------------------------------------------------------------
# Server instance
# ---------------------------------------------------------------------------
resource "hcloud_server" "relay" {
  name        = var.relay_name
  server_type = var.server_type
  image       = var.hcloud_image
  location    = var.hcloud_location
  ssh_keys    = [hcloud_ssh_key.nabu.id]

  user_data = module.relay_cfg.user_data

  firewall_ids = [hcloud_firewall.nabu.id]

  labels = merge(
    {
      "project"      = "nabu"
      "nabu_path_id" = tostring(var.path_id)
      "nabu_region"  = var.region_label
    },
    var.extra_tags
  )

  lifecycle {
    ignore_changes = [user_data]
  }
}
