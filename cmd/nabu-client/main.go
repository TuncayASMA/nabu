package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/TuncayASMA/nabu/pkg/config"
	"github.com/TuncayASMA/nabu/pkg/logger"
	"github.com/TuncayASMA/nabu/pkg/obfuscation"
	"github.com/TuncayASMA/nabu/pkg/socks5"
	"github.com/TuncayASMA/nabu/pkg/transport"
	"github.com/TuncayASMA/nabu/pkg/tunnel"
	"github.com/TuncayASMA/nabu/pkg/version"
)

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port out of range: %d", port)
	}
	return host, port, nil
}

func main() {
	ver := flag.Bool("version", false, "Sürüm bilgisini göster")
	configPath := flag.String("config", config.DefaultClientConfigPath, "Istemci config dosya yolu")
	legacyRelay := flag.String("relay", "", "DEPRECATED: relay host:port (yerine --relay-host ve --relay-port kullanın)")
	relayHost := flag.String("relay-host", config.DefaultDemoRelayHost, "Demo relay host")
	relayPort := flag.Int("relay-port", config.DefaultDemoRelayPort, "Demo relay UDP port")
	legacySocks := flag.String("socks", "", "DEPRECATED: SOCKS dinleme adresi (yerine --socks-listen kullanın)")
	socksListen := flag.String("socks-listen", "127.0.0.1:1080", "SOCKS5 dinleme adresi")
	serveSocks := flag.Bool("serve-socks", true, "Lokal SOCKS5 sunucusunu baslat")
	mode := flag.String("config-mode", config.ConfigModeHybrid, "Config modeli: file-only | flags-only | hybrid")
	psk := flag.String("psk", "", "Pre-shared key (sifreleme): bosssa sifreleme devre disi")
	obfsMode := flag.String("obfuscation", obfuscation.ModeNone, "Obfuscation modu: none | http-connect | websocket")
	obfsProxy := flag.String("obfs-proxy", "", "HTTP CONNECT proxy adresi (host:port) — sadece http-connect modunda kullanılır")
	obfsTLS := flag.Bool("obfs-tls", false, "Relay bağlantısını TLS ile şifrele (DPI kaçınma için; http-connect modunda etkin)")
	obfsTLSInsecure := flag.Bool("obfs-tls-insecure", false, "Relay TLS sertifikasını doğrulama (self-signed sertifikalar için)")
	obfsUTLS := flag.Bool("obfs-utls", false, "TLS parmak izini tarayıcı ile örtüştür (uTLS; --obfs-tls veya --obfs-ws-tls ile birlikte kullanılır)")
	obfsUTLSFingerprint := flag.String("obfs-utls-fingerprint", "chrome", "uTLS tarayıcı parmak izi: chrome | firefox | safari | edge | golang | random")
	salamanderPSK := flag.String("salamander-psk", "", "Salamander UDP obfuscation PSK'sı (relay ile aynı olmalı; sadece UDP modunda geçerli)")
	dnsSecure := flag.Bool("dns-secure", false, "Labyrinth tabanlı güvenli DNS sidecar yapılandırmasını etkinleştir")
	dnsBlockIPv6 := flag.Bool("dns-block-ipv6", false, "IPv6 DNS sızıntısını da engelle (ip6tables gerektirir)")
	dnsProtocol := flag.String("dns-protocol", "doh", "Güvenli DNS protokolü: doh | doh3 | dot")
	dnsServer := flag.String("dns-server", "https://dns.quad9.net/dns-query", "Güvenli DNS upstream sunucusu")
	dnsListen := flag.String("dns-listen", "127.0.0.1:5353", "Yerel güvenli DNS dinleme adresi")
	dnsMetrics := flag.String("dns-metrics", "127.0.0.1:9153", "Labyrinth metrics/dashboard adresi")
	dnsTimeout := flag.Duration("dns-timeout", 5*time.Second, "Güvenli DNS upstream timeout")
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
		if setFlags["relay"] {
			h, p, splitErr := splitHostPort(*legacyRelay)
			if splitErr != nil {
				log.Error("geçersiz --relay değeri", slog.String("relay", *legacyRelay), slog.String("error", splitErr.Error()))
				os.Exit(2)
			}
			cfg.Relay.Host = h
			cfg.Relay.Port = p
		}
		if setFlags["relay-host"] {
			cfg.Relay.Host = *relayHost
		}
		if setFlags["relay-port"] {
			cfg.Relay.Port = *relayPort
		}
		if setFlags["socks"] {
			cfg.Socks5.Listen = *legacySocks
		}
		if setFlags["socks-listen"] {
			cfg.Socks5.Listen = *socksListen
		}
		if setFlags["dns-secure"] {
			cfg.DNS.Enabled = *dnsSecure
		}
		if setFlags["dns-block-ipv6"] {
			cfg.DNS.BlockIPv6 = *dnsBlockIPv6
		}
		if setFlags["dns-protocol"] {
			cfg.DNS.Protocol = *dnsProtocol
		}
		if setFlags["dns-server"] {
			cfg.DNS.Server = *dnsServer
		}
		if setFlags["dns-listen"] {
			cfg.DNS.Listen = *dnsListen
		}
		if setFlags["dns-metrics"] {
			cfg.DNS.Metrics = *dnsMetrics
		}
		if setFlags["dns-timeout"] {
			cfg.DNS.Timeout = dnsTimeout.String()
		}
	}

	cfg.Mode.ConfigMode = *mode
	if err := config.ValidateClientConfig(cfg); err != nil {
		log.Error("client config geçersiz", slog.String("error", err.Error()))
		os.Exit(2)
	}

	relayAddr := fmt.Sprintf("%s:%d", cfg.Relay.Host, cfg.Relay.Port)
	dnsCfg, err := config.BuildDNSConfig(cfg)
	if err != nil {
		log.Error("dns config geçersiz", slog.String("error", err.Error()))
		os.Exit(2)
	}

	log.Info("nabu-client başlıyor",
		slog.String("relay", relayAddr),
		slog.String("socks", cfg.Socks5.Listen),
		slog.String("dns", dnsCfg.UpstreamSummary()),
		slog.String("config", *configPath),
		slog.String("mode", cfg.Mode.ConfigMode),
		slog.String("version", version.Version),
	)

	if dnsCfg.Enabled {
		rules, rulesErr := dnsCfg.LeakPreventionRules()
		if rulesErr != nil {
			log.Error("dns leak prevention kuralları üretilemedi", slog.String("error", rulesErr.Error()))
			os.Exit(2)
		}
		log.Info("güvenli DNS yapılandırması etkin",
			slog.String("protocol", dnsCfg.Protocol),
			slog.String("server", dnsCfg.Server),
			slog.String("listen", dnsCfg.ListenAddr),
			slog.Int("leak_rules", len(rules)),
		)
	}

	if !*serveSocks {
		return
	}

	// Graceful shutdown: cancel context on SIGINT / SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := socks5.NewServer(cfg.Socks5.Listen)
	server.Logger = log

	// Obfuscation factory: nil layer → UDP fallback inside NewRelayHandler.
	obfsLayer, err := obfuscation.NewLayer(*obfsMode, relayAddr, *obfsProxy)
	if err != nil {
		log.Error("obfuscation katmanı başlatılamadı", slog.String("error", err.Error()))
		os.Exit(1)
	}

	applyObfsTLSOptions(obfsLayer, *obfsTLS, *obfsTLSInsecure, *obfsUTLS, *obfsUTLSFingerprint, log, *obfsMode)

	var layer transport.Layer
	if obfsLayer != nil {
		layer = obfsLayer
		log.Info("obfuscation etkin", slog.String("mode", *obfsMode))
	}

	// Salamander is a UDP-only obfuscation layer; incompatible with TCP-based
	// obfuscation modes. When --salamander-psk is set without an obfuscation
	// layer we use the dedicated Salamander handler.
	if *salamanderPSK != "" && layer == nil {
		log.Info("salamander UDP obfuscation etkin")
		server.OnConnect = tunnel.NewRelayHandlerUDPSalamander(relayAddr, []byte(*psk), []byte(*salamanderPSK))
	} else {
		if *salamanderPSK != "" {
			log.Warn("--salamander-psk TCP obfuscation modu ile kullanılamaz; salamander devre dışı")
		}
		server.OnConnect = tunnel.NewRelayHandlerWithLayer(relayAddr, []byte(*psk), layer)
	}

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
