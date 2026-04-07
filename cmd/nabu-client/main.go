package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/TuncayASMA/nabu/pkg/config"
	"github.com/TuncayASMA/nabu/pkg/version"
)

func main() {
	ver := flag.Bool("version", false, "Sürüm bilgisini göster")
	configPath := flag.String("config", config.DefaultClientConfigPath, "Istemci config dosya yolu")
	relayHost := flag.String("relay-host", config.DefaultDemoRelayHost, "Demo relay host")
	relayPort := flag.Int("relay-port", config.DefaultDemoRelayPort, "Demo relay UDP port")
	socksListen := flag.String("socks-listen", "127.0.0.1:1080", "SOCKS5 dinleme adresi")
	mode := flag.String("config-mode", config.ConfigModeHybrid, "Config modeli: file-only | flags-only | hybrid")
	flag.Parse()

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	if *ver {
		fmt.Printf("nabu-client %s (built %s)\n", version.Version, version.BuildTime)
		os.Exit(0)
	}

	if err := config.ValidateConfigMode(*mode); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	cfg := config.DefaultClientConfig()

	if *mode != config.ConfigModeFlagsOnly {
		loadedCfg, err := config.LoadClientConfig(*configPath)
		if err == nil {
			cfg = loadedCfg
		} else if !errors.Is(err, os.ErrNotExist) || *mode == config.ConfigModeFileOnly {
			fmt.Fprintf(os.Stderr, "client config yuklenemedi (%s): %v\n", *configPath, err)
			os.Exit(2)
		}
	}

	if *mode != config.ConfigModeFileOnly {
		if setFlags["relay-host"] {
			cfg.Relay.Host = *relayHost
		}
		if setFlags["relay-port"] {
			cfg.Relay.Port = *relayPort
		}
		if setFlags["socks-listen"] {
			cfg.Socks5.Listen = *socksListen
		}
	}

	cfg.Mode.ConfigMode = *mode
	if err := config.ValidateClientConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "client config invalid: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf(
		"nabu-client basliyor... relay=%s:%d socks=%s config=%s mode=%s\n",
		cfg.Relay.Host,
		cfg.Relay.Port,
		cfg.Socks5.Listen,
		*configPath,
		cfg.Mode.ConfigMode,
	)
}
