package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/TuncayASMA/nabu/pkg/config"
	"github.com/TuncayASMA/nabu/pkg/logger"
	"github.com/TuncayASMA/nabu/pkg/socks5"
	"github.com/TuncayASMA/nabu/pkg/tunnel"
	"github.com/TuncayASMA/nabu/pkg/version"
)

func main() {
	ver := flag.Bool("version", false, "Sürüm bilgisini göster")
	configPath := flag.String("config", config.DefaultClientConfigPath, "Istemci config dosya yolu")
	relayHost := flag.String("relay-host", config.DefaultDemoRelayHost, "Demo relay host")
	relayPort := flag.Int("relay-port", config.DefaultDemoRelayPort, "Demo relay UDP port")
	socksListen := flag.String("socks-listen", "127.0.0.1:1080", "SOCKS5 dinleme adresi")
	serveSocks := flag.Bool("serve-socks", true, "Lokal SOCKS5 sunucusunu baslat")
	mode := flag.String("config-mode", config.ConfigModeHybrid, "Config modeli: file-only | flags-only | hybrid")
	psk := flag.String("psk", "", "Pre-shared key (sifreleme): bosssa sifreleme devre disi")
	logLevel := flag.String("log-level", "info", "Log seviyesi: debug | info | warn | error")
	flag.Parse()

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	if *ver {
		fmt.Printf("nabu-client %s (built %s)\n", version.Version, version.BuildTime)
		os.Exit(0)
	}

	log := logger.NewWithLevel(*logLevel)

	if err := config.ValidateConfigMode(*mode); err != nil {
		log.Error("geçersiz config modu", slog.String("error", err.Error()))
		os.Exit(2)
	}

	cfg := config.DefaultClientConfig()

	if *mode != config.ConfigModeFlagsOnly {
		loadedCfg, err := config.LoadClientConfig(*configPath)
		if err == nil {
			cfg = loadedCfg
		} else if !errors.Is(err, os.ErrNotExist) || *mode == config.ConfigModeFileOnly {
			log.Error("client config yüklenemedi", slog.String("path", *configPath), slog.String("error", err.Error()))
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
		log.Error("client config geçersiz", slog.String("error", err.Error()))
		os.Exit(2)
	}

	relayAddr := fmt.Sprintf("%s:%d", cfg.Relay.Host, cfg.Relay.Port)
	log.Info("nabu-client başlıyor",
		slog.String("relay", relayAddr),
		slog.String("socks", cfg.Socks5.Listen),
		slog.String("config", *configPath),
		slog.String("mode", cfg.Mode.ConfigMode),
		slog.String("version", version.Version),
	)

	if !*serveSocks {
		return
	}

	// Graceful shutdown: cancel context on SIGINT / SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := socks5.NewServer(cfg.Socks5.Listen)
	server.Logger = log
	server.OnConnect = tunnel.NewRelayHandler(relayAddr, []byte(*psk))

	log.Info("SOCKS5 server dinliyor", slog.String("addr", cfg.Socks5.Listen))

	if err := server.ListenAndServeContext(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			log.Info("nabu-client düzgünce kapatıldı")
		} else {
			log.Error("SOCKS5 server hatası", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}
}
