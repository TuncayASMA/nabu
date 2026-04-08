package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TuncayASMA/nabu/pkg/config"
	"github.com/TuncayASMA/nabu/pkg/logger"
	"github.com/TuncayASMA/nabu/pkg/relay"
	"github.com/TuncayASMA/nabu/pkg/version"
)

func main() {
	ver := flag.Bool("version", false, "Sürüm bilgisini göster")
	listenAddr := flag.String("listen", config.DefaultRelayListenAddr, "Relay dinleme adresi")
	region := flag.String("region", config.DefaultDemoRelayRegion, "Relay lokasyonu")
	configPath := flag.String("config", config.DefaultRelayConfigPath, "Relay config dosya yolu")
	wgCompatible := flag.Bool("wg-compatible", true, "WireGuard istemcileriyle uyumlu UDP iletim davranisi")
	serveUDP := flag.Bool("serve-udp", true, "UDP relay listener baslat")
	serveTCP := flag.Bool("serve-tcp", false, "TCP relay listener baslat (HTTPConnect obfuscation için)")
	tcpAddr := flag.String("tcp-addr", ":8443", "TCP relay dinleme adresi (serve-tcp=true ise kullanılır)")
	acceptHTTPConnect := flag.Bool("tcp-http-connect", true, "TCP listener'da HTTP CONNECT handshake bekle")
	psk := flag.String("psk", "", "Pre-shared key (sifreleme): bosssa sifreleme devre disi")
	logLevel := flag.String("log-level", "info", "Log seviyesi: debug | info | warn | error")
	statsAddr := flag.String("stats-addr", "", "HTTP stats endpoint adresi (örn: :9091); bosssa devre disi")
	flag.Parse()

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	log := logger.NewWithLevel(*logLevel)

	if *ver {
		fmt.Printf("nabu-relay %s (built %s)\n", version.Version, version.BuildTime)
		os.Exit(0)
	}

	cfg := config.DefaultRelayConfig()
	loadedCfg, err := config.LoadRelayConfig(*configPath)
	if err == nil {
		cfg = loadedCfg
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Error("relay config yuklenemedi", slog.String("path", *configPath), slog.Any("err", err))
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
		log.Error("relay config gecersiz", slog.Any("err", err))
		os.Exit(2)
	}

	log.Info("nabu-relay basliyor",
		slog.String("listen", cfg.Listen),
		slog.String("region", cfg.Region),
		slog.String("config", *configPath),
		slog.Bool("wg_compatible", cfg.Security.WGCompatible),
		slog.String("version", version.Version),
	)

	if !*serveUDP {
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	udpServer, err := relay.NewUDPServer(cfg.Listen, log)
	if err != nil {
		log.Error("udp relay olusturulamadi", slog.Any("err", err))
		os.Exit(1)
	}
	if *psk != "" {
		udpServer.PSK = []byte(*psk)
	}

	if *statsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", relay.StatsHandler(&udpServer.Stats))
		mux.Handle("/stats", relay.StatsHandler(&udpServer.Stats))
		httpSrv := &http.Server{
			Addr:              *statsAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			log.Info("stats HTTP sunucusu basliyor", slog.String("addr", *statsAddr))
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("stats HTTP sunucusu hatasi", slog.Any("err", err))
			}
		}()
		go func() {
			<-ctx.Done()
			_ = httpSrv.Close()
		}()
	}

	// Start UDP relay in background so TCP relay can run alongside it.
	udpErrCh := make(chan error, 1)
	go func() {
		if err := udpServer.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
			udpErrCh <- err
		} else {
			udpErrCh <- nil
		}
	}()

	// TCP relay (HTTPConnect obfuscation karşı tarafı).
	if *serveTCP {
		tcpServer, err := relay.NewTCPServer(*tcpAddr, log)
		if err != nil {
			log.Error("tcp relay olusturulamadi", slog.Any("err", err))
			os.Exit(1)
		}
		if *psk != "" {
			tcpServer.PSK = []byte(*psk)
		}
		tcpServer.AcceptHTTPConnect = *acceptHTTPConnect
		log.Info("TCP relay başlıyor", slog.String("addr", *tcpAddr), slog.Bool("http_connect", *acceptHTTPConnect))
		go func() {
			if err := tcpServer.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("tcp relay hatasi", slog.Any("err", err))
			}
		}()
	}

	// Wait for UDP relay to finish (primary server).
	if err := <-udpErrCh; err != nil {
		log.Error("udp relay hatasi", slog.Any("err", err))
		os.Exit(1)
	}
}
