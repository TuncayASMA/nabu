package config

import (
	"errors"
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

type RelayConfig struct {
	Listen   string `yaml:"listen"`
	Region   string `yaml:"region"`
	Security struct {
		WGCompatible bool   `yaml:"wg_compatible"`
		TLSProfile   string `yaml:"tls_mimic_profile"`
	} `yaml:"security"`
}

type ClientConfig struct {
	Relay struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"relay"`
	Socks5 struct {
		Listen string `yaml:"listen"`
	} `yaml:"socks5"`
	Mode struct {
		ConfigMode   string `yaml:"config_mode"`
		WGCompatible bool   `yaml:"wg_compatible"`
	} `yaml:"mode"`
}

func DefaultRelayConfig() RelayConfig {
	var cfg RelayConfig
	cfg.Listen = DefaultRelayListenAddr
	cfg.Region = DefaultDemoRelayRegion
	cfg.Security.WGCompatible = true
	cfg.Security.TLSProfile = "chrome-stable"
	return cfg
}

func DefaultClientConfig() ClientConfig {
	var cfg ClientConfig
	cfg.Relay.Host = DefaultDemoRelayHost
	cfg.Relay.Port = DefaultDemoRelayPort
	cfg.Socks5.Listen = "127.0.0.1:1080"
	cfg.Mode.ConfigMode = ConfigModeHybrid
	cfg.Mode.WGCompatible = true
	return cfg
}

func LoadRelayConfig(path string) (RelayConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return RelayConfig{}, err
	}

	cfg := DefaultRelayConfig()
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return RelayConfig{}, fmt.Errorf("relay config parse error: %w", err)
	}

	if err := ValidateRelayConfig(cfg); err != nil {
		return RelayConfig{}, err
	}

	return cfg, nil
}

func LoadClientConfig(path string) (ClientConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ClientConfig{}, err
	}

	cfg := DefaultClientConfig()
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return ClientConfig{}, fmt.Errorf("client config parse error: %w", err)
	}

	if err := ValidateClientConfig(cfg); err != nil {
		return ClientConfig{}, err
	}

	return cfg, nil
}

func ValidateConfigMode(mode string) error {
	switch mode {
	case ConfigModeFileOnly, ConfigModeFlagsOnly, ConfigModeHybrid:
		return nil
	default:
		return fmt.Errorf("invalid config mode %q (allowed: %s, %s, %s)", mode, ConfigModeFileOnly, ConfigModeFlagsOnly, ConfigModeHybrid)
	}
}

func ValidateRelayConfig(cfg RelayConfig) error {
	if cfg.Region == "" {
		return errors.New("region cannot be empty")
	}
	if _, err := net.ResolveUDPAddr("udp", cfg.Listen); err != nil {
		return fmt.Errorf("invalid relay listen address %q: %w", cfg.Listen, err)
	}
	return nil
}

func ValidateClientConfig(cfg ClientConfig) error {
	if cfg.Relay.Host == "" {
		return errors.New("relay host cannot be empty")
	}
	if cfg.Relay.Port < 1 || cfg.Relay.Port > 65535 {
		return fmt.Errorf("relay port out of range: %d", cfg.Relay.Port)
	}
	if _, err := net.ResolveTCPAddr("tcp", cfg.Socks5.Listen); err != nil {
		return fmt.Errorf("invalid socks listen address %q: %w", cfg.Socks5.Listen, err)
	}
	return ValidateConfigMode(cfg.Mode.ConfigMode)
}
