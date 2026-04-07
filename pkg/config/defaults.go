package config

// Package config provides default values and runtime configuration helpers
// for NABU client and relay components.

const (
	DefaultRelayListenAddr  = ":443"
	DefaultRelayConfigPath  = "configs/relay.yaml"
	DefaultClientConfigPath = "configs/client.yaml"

	DefaultDemoRelayRegion = "oci-marseille-fr"
	DefaultDemoRelayHost   = "fr-mrs-1.nabu-relay.net"
	DefaultDemoRelayPort   = 443
)

const (
	ConfigModeFileOnly  = "file-only"
	ConfigModeFlagsOnly = "flags-only"
	ConfigModeHybrid    = "hybrid"
)

const OrganizationMigrationRule = "TuncayASMA/nabu -> nabu-tunnel org (ilk dis PR merge + en az 2 maintainer)"
