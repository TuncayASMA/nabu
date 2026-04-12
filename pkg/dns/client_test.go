package dns

import (
	"strings"
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "disabled_ok", cfg: DefaultConfig()},
		{name: "valid_doh", cfg: Config{Enabled: true, Protocol: ProtocolDoH, Server: "https://dns.quad9.net/dns-query", ListenAddr: DefaultListenAddr, MetricsAddr: DefaultMetricsAddr, Timeout: DefaultTimeout}},
		{name: "valid_doh3", cfg: Config{Enabled: true, Protocol: ProtocolDoH3, Server: "https://dns.example.com/dns-query", ListenAddr: DefaultListenAddr, MetricsAddr: DefaultMetricsAddr, Timeout: DefaultTimeout}},
		{name: "valid_dot", cfg: Config{Enabled: true, Protocol: ProtocolDoT, Server: "dns.quad9.net:853", ListenAddr: DefaultListenAddr, MetricsAddr: DefaultMetricsAddr, Timeout: DefaultTimeout}},
		{name: "missing_server", cfg: Config{Enabled: true, Protocol: ProtocolDoH, ListenAddr: DefaultListenAddr, MetricsAddr: DefaultMetricsAddr, Timeout: DefaultTimeout}, wantErr: true},
		{name: "invalid_protocol", cfg: Config{Enabled: true, Protocol: "bad", Server: "https://dns.quad9.net/dns-query", ListenAddr: DefaultListenAddr, MetricsAddr: DefaultMetricsAddr, Timeout: DefaultTimeout}, wantErr: true},
		{name: "negative_timeout", cfg: Config{Enabled: true, Protocol: ProtocolDoH, Server: "https://dns.quad9.net/dns-query", ListenAddr: DefaultListenAddr, MetricsAddr: DefaultMetricsAddr, Timeout: -1 * time.Second}, wantErr: true},
		{name: "doh_requires_https", cfg: Config{Enabled: true, Protocol: ProtocolDoH, Server: "http://dns.quad9.net/dns-query", ListenAddr: DefaultListenAddr, MetricsAddr: DefaultMetricsAddr, Timeout: DefaultTimeout}, wantErr: true},
		{name: "dot_requires_hostport", cfg: Config{Enabled: true, Protocol: ProtocolDoT, Server: "dns.quad9.net", ListenAddr: DefaultListenAddr, MetricsAddr: DefaultMetricsAddr, Timeout: DefaultTimeout}, wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Fatal("default dns config should be disabled")
	}
	if cfg.Protocol != ProtocolDoH {
		t.Fatalf("default protocol=%s want=%s", cfg.Protocol, ProtocolDoH)
	}
	if cfg.Timeout != DefaultTimeout {
		t.Fatalf("default timeout=%s want=%s", cfg.Timeout, DefaultTimeout)
	}
}

func TestRenderLabyrinthConfig(t *testing.T) {
	cfg := Config{Enabled: true, Protocol: ProtocolDoH3, Server: "https://dns.example.com/dns-query", ListenAddr: DefaultListenAddr, MetricsAddr: DefaultMetricsAddr, Timeout: 7 * time.Second, Blocklists: []string{"https://example.com/hosts|hosts"}}

	yaml, err := cfg.RenderLabyrinthConfig()
	if err != nil {
		t.Fatalf("RenderLabyrinthConfig() error=%v", err)
	}
	for _, want := range []string{
		`listen_addr: 127.0.0.1:5353`,
		`addr: 127.0.0.1:9153`,
		`doh_enabled: true`,
		`doh3_enabled: true`,
		`upstream_timeout: 7s`,
		`enabled: true`,
		`https://example.com/hosts|hosts`,
	} {
		if !strings.Contains(yaml, want) {
			t.Fatalf("rendered config missing %q\n%s", want, yaml)
		}
	}
}

func TestLeakPreventionRules(t *testing.T) {
	cfg := Config{Enabled: true, Protocol: ProtocolDoH, Server: "https://dns.quad9.net/dns-query", ListenAddr: DefaultListenAddr, MetricsAddr: DefaultMetricsAddr, Timeout: DefaultTimeout}
	rules, err := cfg.LeakPreventionRules()
	if err != nil {
		t.Fatalf("LeakPreventionRules() error=%v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules len=%d want=2", len(rules))
	}
	if !strings.Contains(rules[0], "udp --dport 53") {
		t.Fatalf("unexpected first rule: %s", rules[0])
	}
}

func TestLeakPreventionRulesWithIPv6(t *testing.T) {
	cfg := Config{Enabled: true, Protocol: ProtocolDoH, Server: "https://dns.quad9.net/dns-query", ListenAddr: DefaultListenAddr, MetricsAddr: DefaultMetricsAddr, Timeout: DefaultTimeout, BlockIPv6: true}
	rules, err := cfg.LeakPreventionRules()
	if err != nil {
		t.Fatalf("LeakPreventionRules() error=%v", err)
	}
	if len(rules) != 4 {
		t.Fatalf("rules len=%d want=4", len(rules))
	}
	if !strings.Contains(rules[2], "ip6tables") {
		t.Fatalf("expected ipv6 rule, got %s", rules[2])
	}
}

func TestUpstreamSummary(t *testing.T) {
	if got := DefaultConfig().UpstreamSummary(); got != "disabled" {
		t.Fatalf("disabled summary=%q", got)
	}
	cfg := Config{Enabled: true, Protocol: ProtocolDoT, Server: "dns.quad9.net:853"}
	if got := cfg.UpstreamSummary(); got != "DOT via dns.quad9.net:853" {
		t.Fatalf("summary=%q", got)
	}
}