##############################################################################
# OCI (Oracle Cloud Infrastructure) — NABU relay instance
# ARM64 Ampere A1 shape — 1 OCPU / 6 GB RAM (Always Free tier eligible)
#
# Authentication via variables (no hardcoded credentials).
# Required environment variables or tfvars:
#   TF_VAR_tenancy_ocid, TF_VAR_user_ocid, TF_VAR_fingerprint,
#   TF_VAR_private_key_path, TF_VAR_compartment_ocid
##############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 6.0"
    }
  }
}

provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.oci_region
}

# ---------------------------------------------------------------------------
# nabu-relay module (config generator)
# ---------------------------------------------------------------------------
module "relay_cfg" {
  source = "../modules/nabu-relay"

  relay_name  = var.relay_name
  path_id     = var.path_id
  listen_port = var.listen_port
  region_label = var.region_label
  docker_image = var.docker_image
  ssh_public_key = var.ssh_public_key
  nabu_secret = var.nabu_secret
  extra_tags  = var.extra_tags

  # public_ip filled after instance creation (see outputs)
  public_ip   = oci_core_instance.relay.public_ip
}

# ---------------------------------------------------------------------------
# VCN + Subnet
# ---------------------------------------------------------------------------
resource "oci_core_vcn" "nabu" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.relay_name}-vcn"
  cidr_block     = "10.10.0.0/16"
  dns_label      = replace(var.relay_name, "-", "")

  freeform_tags = merge({ "project" = "nabu" }, var.extra_tags)
}

resource "oci_core_internet_gateway" "igw" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.nabu.id
  display_name   = "${var.relay_name}-igw"
  enabled        = true
}

resource "oci_core_route_table" "public" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.nabu.id
  display_name   = "${var.relay_name}-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    network_entity_id = oci_core_internet_gateway.igw.id
  }
}

resource "oci_core_security_list" "nabu" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.nabu.id
  display_name   = "${var.relay_name}-sl"

  # Allow inbound SSH
  ingress_security_rules {
    protocol  = "6" # TCP
    source    = "0.0.0.0/0"
    stateless = false
    tcp_options {
      min = 22
      max = 22
    }
  }

  # Allow inbound NABU relay UDP
  ingress_security_rules {
    protocol  = "17" # UDP
    source    = "0.0.0.0/0"
    stateless = false
    udp_options {
      min = var.listen_port
      max = var.listen_port
    }
  }

  # Allow inbound NABU probe UDP
  ingress_security_rules {
    protocol  = "17" # UDP
    source    = "0.0.0.0/0"
    stateless = false
    udp_options {
      min = var.listen_port + 1000
      max = var.listen_port + 1000
    }
  }

  # Allow all outbound
  egress_security_rules {
    protocol    = "all"
    destination = "0.0.0.0/0"
    stateless   = false
  }
}

resource "oci_core_subnet" "public" {
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.nabu.id
  display_name      = "${var.relay_name}-subnet"
  cidr_block        = "10.10.1.0/24"
  route_table_id    = oci_core_route_table.public.id
  security_list_ids = [oci_core_security_list.nabu.id]
  dns_label         = "pub"
}

# ---------------------------------------------------------------------------
# SSH key
# ---------------------------------------------------------------------------
resource "oci_core_instance_configuration" "relay" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.relay_name}-cfg"

  instance_details {
    instance_type = "compute"
    launch_details {
      shape = "VM.Standard.A1.Flex"
      shape_config {
        ocpus         = 1
        memory_in_gbs = 6
      }
      source_details {
        source_type = "image"
        image_id    = var.oci_image_id
      }
      metadata = {
        "ssh_authorized_keys" = var.ssh_public_key
        "user_data"           = base64encode(module.relay_cfg.user_data)
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Instance
# ---------------------------------------------------------------------------
resource "oci_core_instance" "relay" {
  compartment_id      = var.compartment_ocid
  availability_domain = var.availability_domain
  display_name        = var.relay_name
  shape               = "VM.Standard.A1.Flex"

  shape_config {
    ocpus         = 1
    memory_in_gbs = 6
  }

  source_details {
    source_type = "image"
    image_id    = var.oci_image_id
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.public.id
    display_name     = "${var.relay_name}-vnic"
    assign_public_ip = true
  }

  metadata = {
    "ssh_authorized_keys" = var.ssh_public_key
    "user_data"           = base64encode(module.relay_cfg.user_data)
  }

  freeform_tags = merge(
    {
      "project"        = "nabu"
      "nabu.path_id"   = tostring(var.path_id)
      "nabu.region"    = var.region_label
    },
    var.extra_tags
  )

  lifecycle {
    ignore_changes = [metadata["user_data"]]
  }
}
