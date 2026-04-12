package dns

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ProtocolDoH  = "doh"
	ProtocolDoH3 = "doh3"
	ProtocolDoT  = "dot"
)

const (
	DefaultListenAddr  = "127.0.0.1:5353"
	DefaultMetricsAddr = "127.0.0.1:9153"
	DefaultTimeout     = 5 * time.Second
	MinTimeout         = 1 * time.Second
	MaxTimeout         = 30 * time.Second
)

type Config struct {
	Enabled     bool
	Protocol    string
	Server      string
	ListenAddr  string
	MetricsAddr string
	Timeout     time.Duration
	Blocklists  []string
	BlockIPv6   bool
}

func DefaultConfig() Config {
	return Config{
		Enabled:     false,
		Protocol:    ProtocolDoH,
		Server:      "https://dns.quad9.net/dns-query",
		ListenAddr:  DefaultListenAddr,
		MetricsAddr: DefaultMetricsAddr,
		Timeout:     DefaultTimeout,
		BlockIPv6:   false,
	}
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Server == "" {
		return fmt.Errorf("dns server cannot be empty")
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("dns timeout must be positive")
	}
	if c.Timeout < MinTimeout || c.Timeout > MaxTimeout {
		return fmt.Errorf("dns timeout must be between 1s and 30s")
	}
	if _, err := net.ResolveUDPAddr("udp", c.ListenAddr); err != nil {
		return fmt.Errorf("invalid dns listen address %q: %w", c.ListenAddr, err)
	}
	if c.MetricsAddr != "" {
		if _, err := net.ResolveTCPAddr("tcp", c.MetricsAddr); err != nil {
			return fmt.Errorf("invalid dns metrics address %q: %w", c.MetricsAddr, err)
		}
	}

	switch c.Protocol {
	case ProtocolDoH, ProtocolDoH3:
		u, err := url.Parse(c.Server)
		if err != nil {
			return fmt.Errorf("invalid dns url %q: %w", c.Server, err)
		}
		if u.Scheme != "https" {
			return fmt.Errorf("%s requires https url, got %q", c.Protocol, c.Server)
		}
		if u.Host == "" {
			return fmt.Errorf("dns url host cannot be empty")
		}
	case ProtocolDoT:
		if _, _, err := net.SplitHostPort(c.Server); err != nil {
			return fmt.Errorf("dot server must be host:port, got %q: %w", c.Server, err)
		}
	default:
		return fmt.Errorf("unsupported dns protocol %q", c.Protocol)
	}

	return nil
}

func (c Config) RenderLabyrinthConfig() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	type serverConfig struct {
		ListenAddr string `yaml:"listen_addr"`
		DoTEnabled bool   `yaml:"dot_enabled,omitempty"`
	}
	type resolverConfig struct {
		MaxDepth          int    `yaml:"max_depth"`
		QNAMEMinimization bool   `yaml:"qname_minimization"`
		PreferIPv4        bool   `yaml:"prefer_ipv4"`
		DNSSECEnabled     bool   `yaml:"dnssec_enabled"`
		UpstreamTimeout   string `yaml:"upstream_timeout"`
	}
	type cacheConfig struct {
		MaxEntries int `yaml:"max_entries"`
		MinTTL     int `yaml:"min_ttl"`
		MaxTTL     int `yaml:"max_ttl"`
	}
	type webConfig struct {
		Enabled    bool   `yaml:"enabled"`
		Addr       string `yaml:"addr"`
		DoHEnabled bool   `yaml:"doh_enabled"`
		DoH3       bool   `yaml:"doh3_enabled"`
		TLSEnabled bool   `yaml:"tls_enabled"`
	}
	type blocklistConfig struct {
		Enabled bool     `yaml:"enabled"`
		Lists   []string `yaml:"lists,omitempty"`
	}
	type labyrinthConfig struct {
		Server    serverConfig    `yaml:"server"`
		Resolver  resolverConfig  `yaml:"resolver"`
		Cache     cacheConfig     `yaml:"cache"`
		Web       webConfig       `yaml:"web"`
		Blocklist blocklistConfig `yaml:"blocklist,omitempty"`
	}

	cfg := labyrinthConfig{
		Server: serverConfig{
			ListenAddr: c.ListenAddr,
			DoTEnabled: c.Protocol == ProtocolDoT,
		},
		Resolver: resolverConfig{
			MaxDepth:          30,
			QNAMEMinimization: true,
			PreferIPv4:        true,
			DNSSECEnabled:     true,
			UpstreamTimeout:   c.Timeout.String(),
		},
		Cache: cacheConfig{MaxEntries: 100000, MinTTL: 5, MaxTTL: 86400},
		Web: webConfig{
			Enabled:    true,
			Addr:       c.MetricsAddr,
			DoHEnabled: c.Protocol == ProtocolDoH || c.Protocol == ProtocolDoH3,
			DoH3:       c.Protocol == ProtocolDoH3,
			TLSEnabled: false,
		},
		Blocklist: blocklistConfig{Enabled: len(c.Blocklists) > 0, Lists: c.Blocklists},
	}

	b, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshal labyrinth config: %w", err)
	}
	return string(b), nil
}

func (c Config) LeakPreventionRules() ([]string, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !c.Enabled {
		return nil, nil
	}
	rules := []string{
		"iptables -A OUTPUT -p udp --dport 53 -j DROP",
		"iptables -A OUTPUT -p tcp --dport 53 -j REJECT",
	}
	if c.BlockIPv6 {
		rules = append(rules,
			"ip6tables -A OUTPUT -p udp --dport 53 -j DROP",
			"ip6tables -A OUTPUT -p tcp --dport 53 -j REJECT",
		)
	}
	return rules, nil
}

func (c Config) UpstreamSummary() string {
	if !c.Enabled {
		return "disabled"
	}
	protocol := c.Protocol
	if protocol == "" {
		protocol = "unknown"
	}
	return fmt.Sprintf("%s via %s", strings.ToUpper(protocol), c.Server)
}
