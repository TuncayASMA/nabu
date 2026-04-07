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
	listenAddr := flag.String("listen", config.DefaultRelayListenAddr, "Relay dinleme adresi")
	region := flag.String("region", config.DefaultDemoRelayRegion, "Relay lokasyonu")
	configPath := flag.String("config", config.DefaultRelayConfigPath, "Relay config dosya yolu")
	wgCompatible := flag.Bool("wg-compatible", true, "WireGuard istemcileriyle uyumlu UDP iletim davranisi")
	flag.Parse()

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	if *ver {
		fmt.Printf("nabu-relay %s (built %s)\n", version.Version, version.BuildTime)
		os.Exit(0)
	}

	cfg := config.DefaultRelayConfig()
	loadedCfg, err := config.LoadRelayConfig(*configPath)
	if err == nil {
		cfg = loadedCfg
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "relay config yuklenemedi (%s): %v\n", *configPath, err)
		os.Exit(2)
	}

	if setFlags["listen"] {
		cfg.Listen = *listenAddr
	}
	if setFlags["region"] {
		cfg.Region = *region
	}
	if setFlags["wg-compatible"] {
		cfg.Security.WGCompatible = *wgCompatible
	}

	if err := config.ValidateRelayConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "relay config invalid: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf(
		"nabu-relay basliyor... listen=%s region=%s config=%s wg_compatible=%t\n",
		cfg.Listen,
		cfg.Region,
		*configPath,
		cfg.Security.WGCompatible,
	)
}
