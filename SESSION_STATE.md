# NABU — SESSION STATE
# Bu dosyayı her oturum başında oku, her oturum sonunda güncelle.

## Son Güncelleme
Tarih: 2026-04-11
Oturum: 1.38 (Tamamlandı — commit c01485d)

## Mevcut Faz / Sprint / Oturum
- Faz: 2 — QUIC Maskeleme + Obfuscation Layer
- Sprint: 10-13 — Micro-Phantom + DPI Test + Governor
  - ✅ HTTPConnect obfuscation layer (Oturum 1.21-1.22)
  - ✅ TCPServer TLS wrapping (Oturum 1.23)
  - ✅ Anti-replay window + client TLS dialer (Oturum 1.24)
  - ✅ WebSocket obfuscation RFC 6455 (Oturum 1.25)
  - ✅ uTLS Chrome/Firefox/Edge fingerprint (Oturum 1.26)
  - ✅ Salamander UDP obfuscation AES-256-GCM (Oturum 1.27)
  - ✅ Probe defense + aktif prob savunması (Oturum 1.28)
  - ✅ QUIC/H3 transport — QUICServer + QUICLayer (Oturum 1.29)
  - ✅ JA3/JA4 parmak izi normalizasyonu (Oturum 1.30)
  - ✅ Micro-Phantom Trafik Profil Motoru (Oturum 1.31)
  - ✅ Governor Adaptif Hız Kontrolcüsü (Oturum 1.32)
  - ✅ Phantom DPI İstatistiksel Testler — KS-test, BucketFrequency, Shannon (Oturum 1.33)
  - ✅ nDPI / Suricata Docker entegrasyon testi (Oturum 1.34)
  - ✅ Multipath QUIC Scheduler — MinRTT+BLEST+Redundant+WRR (Oturum 1.35)
  - ✅ Relay Ağı Konfigürasyonu — MultiPathConn + UDP echo probe (Oturum 1.36)
  - ✅ Terraform Relay Provisioning — OCI ARM64 + Hetzner CAX11 (Oturum 1.37)
  - ✅ eBPF Governor — TC hook + ring buffer + Go wrapper (Oturum 1.38)
  - 🔜 Governor Karar Motoru — eBPF entegrasyonu + karar döngüsü (Oturum 1.39)
- Oturum: 1.38 → Sonraki: 1.39

## Bir Sonraki Oturum İlk Görevi
```
Oturum 1.39 — Governor Karar Motoru (Sprint 17.4-18.2 — RUNBOOK §18):
1. pkg/governor/governor.go: eBPF Monitor entegrasyonu
   - NewMonitor(iface, bufSize) çağrısı
   - 100ms karar döngüsü: eBPF Snapshot → adaptif hız hesabı
   - Outputs: phantomRate, schedulerBias, fecRatio, burstMode
2. pkg/governor/ebpf entegrasyon testi (gerçek iface varsa)
3. PROTOCOL.md v2.8: §28 Governor Karar Motoru
```

## Oturum 1.38 Özeti
- pkg/governor/ebpf/bpf/nabu_monitor.c: TC clsact hook kernel programı
  * BPF_MAP_TYPE_ARRAY nabu_counters[2] (ingress/egress packet+bytes)
  * BPF_MAP_TYPE_PERCPU_ARRAY nabu_last_ts[2] (IAT hesabı)
  * BPF_MAP_TYPE_RINGBUF nabu_events (4 MiB IAT olay akışı)
  * nabu_event{ts_ns, iat_ns, pkt_len, direction} — her pakette push
- pkg/governor/ebpf/monitor.go: Monitor Go wrapper
  * monitorImpl interface: attach/readEvents/counters/close
  * Start (idempotent, 2 goroutine), Stop (WaitGroup drain), Events, Snapshot
  * go:generate bpf2go directive
- pkg/governor/ebpf/impl_stub.go: no-op backend (CI/no-clang ortamı için güvenli)
- pkg/governor/ebpf/impl_linux_real.go: gerçek bpf2go backend (//go:build ignore)
- pkg/governor/ebpf/monitor_test.go: 13 test — tümü PASS (-race)
- docs/PROTOCOL.md: v2.6 → v2.7 — §27 eBPF Governor
- go.mod: github.com/cilium/ebpf v0.21.0 eklendi
- Full test suite: tüm PASS

## Oturum 1.37 Özeti
- deploy/terraform/modules/nabu-relay/: cloud-agnostic relay config modülü
  * main.tf: cloud-init user-data + nabu_config_snippet locals
  * variables.tf: relay_name, path_id, listen_port, nabu_secret (sensitive)
  * outputs.tf: user_data (sensitive), nabu_config_snippet, nabu_endpoint, probe_port
- deploy/terraform/oci/: OCI Ampere A1 Flex ARM64 (eu-marseille-1, path-id 0, port 7001)
  * VCN + IGW + Route Table + Security List + Subnet + Instance
  * TCP/22 + UDP/7001 + UDP/8001 (probe) — Always Free eligible
  * Tüm credentials TF_VAR_* ile (sensitive=true, hardcode yok)
- deploy/terraform/hetzner/: Hetzner CAX11 ARM64 (fsn1, path-id 1, port 7002)
  * Firewall + SSH key + Server (cax11 2vCPU 4GB ~€4/mo)
  * TCP/22 + UDP/7002 + UDP/8002 (probe)
- docs/PROTOCOL.md: v2.5 → v2.6 — §26 Terraform Relay Provisioning
- Full test suite: tüm PASS

## Oturum 1.36 Özeti
- pkg/multipath/conn.go: MultiPathConn path lifecycle manager
  * RelayEndpoint + PingOptions structs
  * Background UDP echo probe loop (probe_port = relay_port + 1000)
  * Start/Stop (idempotent), SelectPath, Stats, UpdateStats
  * deriveProbeAddr: port+1000 convention
  * ctx param blanked (_) — unparam lint fix
- pkg/multipath/conn_test.go: 13 unit test, hepsi -race ile PASS
  * Real UDP echo server integration test (ProbeReachable)
  * Unreachable relay stays unavailable (ProbeUnreachable)
- deploy/docker/relay-network.yml: multi-relay Docker Compose
  * nabu-relay-fr (OCI FR, path-id=0, port 7001)
  * nabu-relay-de (Hetzner DE, path-id=1, port 7002)
  * nabu-client-mp (NABU_SCHEDULER env selector)
- docs/PROTOCOL.md: v2.4 → v2.5 — §25 Relay Network Architecture
- gofmt + golangci-lint: temiz

## Oturum 1.35 Özeti
- pkg/multipath/scheduler.go: 4 path-selection scheduler
  * MinRTTScheduler: EWMA α=0.125, QUIC RFC 9002 uyumlu, en düşük RTT path seçer
  * BLESTScheduler: HoL-blocking tahmin, score=RTT/(1-loss)+λ·max(0,queueDepth-50ms)
  * RedundantScheduler: tüm available path'lara kopyala, MaxCopies sınırı, tek path için MinRTT fallback
  * WeightedRRScheduler: deficit tabanlı WRR, bandwidth oranları korunur, ZeroBW → 1 byte/s güvenli
  * Tüm scheduler'lar sync.Mutex ile thread-safe
- pkg/multipath/scheduler_test.go: 19 unit test, hepsi -race ile PASS
  * MinRTT: 6 test (seçim/skip/allUnavail/empty/EWMA/single)
  * BLEST: 5 test (queue/rtt/unavail/allUnavail/loss-adjusted)
  * Redundant: 4 test (selectAll/maxCopies/delegate/noPaths)
  * WeightedRR: 4 test (distribution/unavail/allUnavail/zeroBW)
- docs/PROTOCOL.md: v2.4 — §24 Multipath QUIC Scheduler (MinRTT/BLEST/Redundant/WRR math formulas, test table)
- gofmt + golangci-lint: temiz (unused field kaldırıldı)

## Oturum 1.34 Özeti
- test/dpi/ndpi_test.go: nDPI protokol sınıflandırma entegrasyon testleri
  * TestNDPI_TLSClientHello: 5 × TLS 1.3 ClientHello → ndpiReader → "TLS packets:5" — PASS
  * TestNDPI_PhantomShapedTraffic: 32 KB Phantom-shaped → ndpiReader → "TLS packets:27" — PASS
  * ndpiReader v4.2.0 (libndpi-bin ARM64 apt paketi, /usr/bin/ndpiReader)
  * Pure Go PCAP yazıcı: writePcapGlobalHeader, writePcapRecord, buildEthernetFrame, tlsClientHello
  * DATA RACE düzeltmesi: goroutine-owned collected slice, channel-driven write loop
- test/dpi/suricata_test.go: Suricata IDS sıfır-alert testi
  * TestSuricata_ZeroAlertsOnTLS: 27-paket TLS PCAP → 0 Suricata alert — PASS
  * TestSuricata_PositiveControl: SSH banner → SID 9000003 ateşlendi — PASS
  * jasonish/suricata:latest Docker v8.0.4 (ARM64), offline PCAP-read modu
  * 5 özel kural (SID 9000001-9000005): OpenVPN/WireGuard/SSH/Shadowsocks/Tor
  * eve.json ayrıştırma: event_type="alert" varlığı kontrolü
- docs/PROTOCOL.md: v2.3 — §23 nDPI + Suricata Integration Tests, Changelog 2.3 eklendi
- Tüm testler PASS: 11/11 test/dpi + tüm paketler

## Oturum 1.33 Özeti
- pkg/phantom/stat/ks.go: DPI istatistiksel test araçları
  * KSTest(sample, cdf): Kolmogorov-Smirnov, Marsaglia asimptotik p-değeri
    P(D_n > d) ≈ 2·Σ(-1)^(k-1)·exp(-2k²t²), t = d·√n
  * referenceCDF(x, cdf): parçalı-doğrusal interpolasyon (sürekli dağılımlar için)
  * BucketFrequencyTest(sample, cdf, tolerance): paket boyutu için
    Her kova gözlenen p beklenen p'nin %60'ı dahilinde → PASS
    Seyrek kovalar (expected < %1) atlanır
  * ShannonEntropy(data): H = -Σ p·log₂(p) bit/byte
- pkg/phantom/stat/ks_test.go: 15 unit test — hepsi PASS
  * KSTest: SameDistribution (p=0.39)/Different/Empty/SinglePoint
  * ReferenceCDF: sınır koşulları
  * KSPValue: Zero (p=1)/Large (p≈0)
  * ShannonEntropy: Random (7.98 bits)/Zeros/TwoSymbols/Empty
  * BucketFrequencyTest: Uniform/AllZeros/EmptySample
- test/dpi/phantom_test.go: 7 DPI entegrasyon testi — hepsi PASS
  * TestProfile_{web_browsing,youtube_sd,instagram_feed}_PacketSizeDist
    n=2000 örnekleme, BucketFrequencyTest %60 tolerans
  * TestProfile_{web_browsing,youtube_sd,instagram_feed}_IATDist
    n=2000 örnekleme, BucketFrequencyTest %60 tolerans
  * TestPhantomShaper_ShannonEntropy: 32KB net.Pipe, H=6.33 bits > 3.0 eşik
- docs/PROTOCOL.md: v2.2 — §22 DPI Statistical Test Framework, Changelog 2.2 eklendi
- gofmt + golangci-lint: temiz

**Temel Tasarım Kararı — KS vs BucketFrequency:**
sampleCDF ayrık kovalar (n=20) üretir; KS testi büyük n'de her zaman reddeder
(D~0.07-0.15 → p≈0). Çözüm: BucketFrequencyTest — her kova için göreli tolerans
kontrolü, discrete-bucket yapısıyla uyumlu.

## Oturum 1.32 Özeti
- pkg/governor/governor.go: Adaptif hız kontrolcüsü
  * ReadProcNetDev(path): /proc/net/dev çok arayüz ayrıştırıcı
  * TimeOfDayCoeff(t): kosinus eğrisi, peak 20:00, floor 0.30 (tıkanan=0.30)
    Formül: raw = 0.5*(1 - cos(2π*(h-8)/24)); clamp(raw, 0.30, 1.00)
  * ComputeThroughput(a,b Snapshot): bayt/s hesaplama, sayaç sarma güvenli
  * Governor.Run(ctx): her PollInterval (=2s) /proc okur, Recommendation kanalına gönderir
  * Governor.LastRecommendation(): son öneriyi thread-safe döndürür
  * NowFunc enjekte edilebilir — deterministik testler için
- pkg/governor/governor_test.go: 13 test, -race geçti
  * TODCoeff: peak/trough/range/midnight
  * ReadProcNetDev: alanlar/loopback/hatalı-yol
  * ComputeThroughput: temel/sıfır-dt/sayaç-sarma
  * Governor.Run: öneri-üretir/temiz-iptal/LastRecommendation
- docs/PROTOCOL.md: v2.1 — §21 Governor, Changelog 2.1 eklendi
- gofmt + golangci-lint: temiz

## Oturum 1.31 Özeti
- pkg/phantom/profiles/profile.go: TrafficProfile struct, 20-nokta CDF örnekleme
  * sampleCDF(): ters dönüşüm örnekleme, u~Uniform(0,1)
  * Validate(): monotonluk, uzunluk, terminal=1.0 kontrolleri
  * SamplePacketSize/SampleIATMs, LoadFromFile/LoadEmbedded/EmbeddedNames
- pkg/phantom/profiles/embedded.go: 3 gömülü profil
  * web_browsing: bimodal paket boyutu (40B ACK + 1400B veri), 30-60ms IAT
  * youtube_sd: büyük paketler (streaming), 10-30ms IAT, uzun burst
  * instagram_feed: karma (API + medya), 100-200ms IAT (insan ritmi)
- pkg/phantom/profiles/{web,youtube,instagram}.json: JSON serileştirmeleri
- pkg/phantom/shaper/shaper.go: net.Conn sarmalayıcı
  * tokenBucket: özel hız sınırlayıcı (dış bağımlılık yok)
  * Write(): profil boyutlu segmentlere bölme + IAT gecikmeleri
  * GenerateIdle(ctx, duration): sentetik kapak trafiği üretimi
  * SetProfile(): sıcak profil değiştirme (runtime)
- Test: 14 profil + 13 shaper testi, hepsi -race ile geçti
- docs/PROTOCOL.md: v2.0 — §20 Micro-Phantom Traffic Profile Engine, Changelog 2.0 eklendi
- gofmt + golangci-lint: temiz

## Oturum 1.30 Özeti
- pkg/obfuscation/ja3_normalizer.go: JA3/JA4 TLS parmak izi normalizasyonu
  * Profile tipi: Chrome133/Firefox120/Edge85/Random
  * ComputeJA3String/CipherString/Hash (GREASE RFC 8701 dışlama)
  * isGREASEValue: (v&0x0f0f==0x0a0a)&&(v>>8==v&0xff) doğru implementasyon
  * Firefox JA3 hash deterministik: 7fbdc1beb9b27dfb24f94e3a7f2112af
  * Chrome cipher string deterministik (uTLS ShuffleChromeTLSExtensions sadece extension sırası)
  * UTLSDialNormalized: tarayıcı profil TLS handshake yardımcısı
- pkg/obfuscation/ja3_normalizer_test.go: 20 test
  * GREASE, profiller, cipher string, hash, dial testleri
  * Random profil: HelloRandomized uyumsuzluğu tolerant test
- docs/PROTOCOL.md: v1.9 — §19 JA3/JA4 Fingerprint Normalization, Changelog eklendi

## Oturum 1.29 Özeti
- pkg/relay/quic_server.go: QUICServer — QUIC/TLS-1.3 listener, NABU frames over
  QUIC streams, ALPN nabu/1+h3, ProbeDefense, PSK, ReplayWindow, anti-HOL-blocking
  multiplexing — 3/3 unit test geçti
- pkg/obfuscation/quic_layer.go: QUICLayer — client-side transport.Layer, connection
  multiplexing via OpenStreamSync, TLS config auto-ALPN
- test/integration/quic_test.go: 3/3 integration test geçti (PingPong, ConnectEcho,
  MultiStream concurrency)
- cmd/nabu-relay/main.go: --serve-quic/--quic-addr/--quic-cert/--quic-key flags
- docs/PROTOCOL.md: v1.8 — §18 QUIC/H3 Transport eklendi
- go.mod: quic-go v0.59.0 direkt bağımlılık

## Tamamlananlar
- [x] RUNBOOK.md oluşturuldu
- [x] Proje dizin yapısı oluşturuldu (/home/ubuntu/nabu/)
- [x] SESSION_STATE.md oluşturuldu
- [x] Proje hafızaya kaydedildi (/memories/repo/nabu-project.md)
- [x] Go 1.26.1 linux/arm64 kuruldu (/usr/local/go)
- [x] go mod init github.com/TuncayASMA/nabu
- [x] Makefile (build/test/lint/cross-compile)
- [x] AGPL-3.0 LICENSE
- [x] .github/workflows/ci.yml (test + lint + 4 platform matrix)
- [x] cmd/nabu-client/main.go + cmd/nabu-relay/main.go
- [x] pkg/version/version.go (ldflags inject)
- [x] İlk git commit: ead609e
- [x] GitHub repo oluşturuldu ve push edildi: https://github.com/TuncayASMA/nabu
- [x] Module path güncellendi: github.com/TuncayASMA/nabu
- [x] Config kararları kodlandı: UDP/443, OCI Marseille, hybrid mode, WG compatible
- [x] configs/client.yaml + configs/relay.yaml eklendi
- [x] pkg/config: YAML load + validation eklendi
- [x] pkg/crypto: AES-256-GCM Encrypt/Decrypt eklendi
- [x] pkg/crypto: HKDF-SHA256 session key derivation eklendi
- [x] pkg/crypto: NonceGenerator + concurrency testleri eklendi
- [x] pkg/crypto testleri geçti
- [x] pkg/socks5: handshake + request parsing (IPv4/IPv6/domain)
- [x] pkg/socks5: timeout, panic recovery, conn limit, context shutdown
- [x] pkg/socks5 testleri geçti
- [x] cmd/nabu-client: --serve-socks ile lokal socks5 başlatma eklendi
- [x] pkg/transport: Frame encode/decode (header + payload)
- [x] pkg/transport: UDPClient Connect/SendFrame/ReceiveFrame/Close eklendi
- [x] pkg/transport testleri geçti
- [x] pkg/relay: UDP listener skeleton eklendi
- [x] cmd/nabu-relay: --serve-udp entegrasyonu eklendi
- [x] relay paket testleri geçti
- [x] pkg/relay: stream state timeout cleanup (sync.Map, 30s) eklendi
- [x] pkg/relay: ACK helper refactor (sendACKFrame) tamamlandi
- [x] pkg/socks5: CONNECT success response scaffold eklendi
- [x] pkg/socks5: OnConnect hook ile relay forwarding baglandi
- [x] pkg/tunnel: SOCKS5 CONNECT -> UDP relay bridge eklendi
- [x] pkg/relay: CONNECT/DATA/FIN frame dispatch ile target TCP forwarding eklendi
- [x] test/integration: SOCKS5 -> relay -> target echo testi eklendi
- [x] Tüm Go testleri geçti (go test ./...)
- [x] pkg/tunnel: stop-and-wait ACK wait/retry (max 3) eklendi
- [x] pkg/tunnel: connect ACK timeout davranisi eklendi
- [x] pkg/tunnel: FIN ve FIN-ACK send error handling eklendi
- [x] pkg/tunnel testleri eklendi (ACK match + timeout)
- [x] pkg/relay: StreamState → NextExpectedSeq + reorderBuf (cap 64) + maxBufFrames
- [x] pkg/relay: handleDataFrame → tam OOO/duplicate/backpressure mantığı
- [x] pkg/relay: 4 yeni unit test (init, buffer, drain, backpressure)
- [x] pkg/tunnel: sendFrameWithRetry → exponential backoff (300ms → 4s)
- [x] test/integration: reliability_test.go — TestDuplicateDataFrameIsIgnored PASS
- [x] test/integration: TestOutOfOrderDataFrameDeliveredInOrder PASS
- [x] git commit f9c13ff + push → main
- [x] pkg/transport: FlagHandshake=0x40, Frame struct, var bloğu düzeltildi
- [x] pkg/transport/udp_client.go: SessionKey []byte, SendFrame encrypt, ReceiveFrame decrypt
- [x] pkg/relay/udp_server.go: PSK field, sessions sync.Map, handleHandshakeFrame (HKDF),
      sendHandshakeACK (plaintext), sendFrame AES-GCM encrypt, main loop decrypt
- [x] pkg/tunnel/relay_handler.go: performHandshake() (32-byte salt + HKDF), NewRelayHandler(addr, psk)
- [x] cmd/nabu-client + cmd/nabu-relay: --psk flag eklendi
- [x] test/integration/encryption_test.go: TestEncryptedTunnelEcho PASS, TestEncryptedTunnelMultiPayload PASS
- [x] Tüm testler geçti (go test ./...)
- [x] pkg/crypto/x25519.go: GenerateX25519KeyPair, X25519SharedSecret, DeriveSessionKeyX25519
- [x] pkg/crypto/x25519_test.go: symmetry, determinism, both-sides-agree, forward-secrecy unit testleri
- [x] pkg/relay/udp_server.go: handleHandshakeFrame → X25519 DH, sendHandshakeACK relay pubkey taşıyor
- [x] pkg/relay/udp_server.go: PSK auth reject — session key olmadan gelen frame'ler DROP
- [x] pkg/tunnel/relay_handler.go: performHandshake → X25519 DH
- [x] test/integration/encryption_test.go: TestNoPSKClientRejectedByPSKRelay PASS
- [x] git commit 24005d7 + push → main
- [x] pkg/relay/ratelimit.go: TokenBucket (goroutine-safe, token refill), RateLimiterMap
- [x] UDPServer.RateLimitPPS field, main loop'ta Drop+Warn entegrasyonu
- [x] pkg/relay/ratelimit_test.go: Allow / Exhausted / Refill / Isolation / Concurrency PASS
- [x] test/integration: TestRateLimitDropsExcessFrames PASS
- [x] git commit 3c574fe (Oturum 1.12)
- [x] pkg/transport/frame.go: FlagPing=0x08, FlagPong=0x10 eklendi
- [x] pkg/transport/udp_client.go: MeasureRTT() — Ping gönder, Pong bekle, süre döndür
- [x] pkg/relay/udp_server.go: FlagPing → FlagPong yanıt (Seq → Ack echo)
- [x] pkg/tunnel/relay_handler.go: post-handshake RTT ölçümü; baseTimeout=2×RTT+slop
  sendFrameWithRetry + pipeConnToRelay baseTimeout parametresi aldı
- [x] pkg/transport/udp_client_test.go: TestMeasureRTTPingPong + TestMeasureRTTTimeout PASS
- [x] Tüm testler geçti (go test ./...)
- [x] git commit cb7eefa (Oturum 1.13)
- [x] deploy/docker/Dockerfile.relay + Dockerfile.client (distroless ARM64)
- [x] deploy/docker/docker-compose.yml (relay + client servisleri, .env desteği)
- [x] deploy/docker/.env.example
- [x] deploy/systemd/nabu-relay.service + nabu-client.service (hardened)
- [x] deploy/systemd/relay.env.example + client.env.example
- [x] RUNBOOK.md: Docker Compose + systemd deployment bölümü eklendi
- [x] git commit 582bf35 (Oturum 1.14)
- [x] pkg/relay/udp_server.go: Stats (BytesIn/BytesOut/ActiveStreams/DroppedFrames) + graceful shutdown FIN broadcast
- [x] pkg/relay/udp_server_test.go: TestUDPServerStats PASS
- [x] git commit 060bd78 (Oturum 1.15)
- [x] test/integration/rtt_test.go: TestMeasureRTTOnLiveRelay + TestRTTAdaptiveBackoffEndToEnd + TestRTTMultipleRoundTrips PASS
- [x] docs/PROTOCOL.md: wire format, handshake akışı, şifreleme katmanı dokümantasyonu
- [x] git commit 33ecc77 (Oturum 1.16)
- [x] pkg/logger/logger.go: JSON slog handler + sensitive field redaction
- [x] cmd/nabu-relay/main.go: --log-level flag, structured slog, relay.NewUDPServer(cfg.Listen, log)
- [x] git commit d83e167 (Oturum 1.17)
- [x] .github/workflows/ci.yml: Go 1.26.x, lint-first, -race, integration tests, coverage ≥60%, multi-arch build
- [x] .golangci.yml: errcheck, gosimple, govet, ineffassign, staticcheck, unused, gofmt, goimports, misspell, gosec
- [x] pkg/tunnel/relay_handler.go: data race fix — remove deferred ReadTimeout reset
- [x] test/integration/helpers_test.go: startConfiguredRelay() + t.Cleanup cancel+wait pattern
- [x] Tüm integration testler startConfiguredRelay'e taşındı (relay goroutine port reuse race fix)
- [x] go test -race geçiyor: 3/3 ardışık geçiş (7 paket, 0 FAIL)
- [x] git commit d3a0df8 (Oturum 1.18)
- [x] pkg/transport/layer.go: Layer, RTTMeasurer, ReadTimeoutSetter, SessionKeySetter interfaces
- [x] pkg/transport/udp_client.go: SetReadTimeout/SetSessionKey methods + compile-time assertions
- [x] pkg/tunnel/relay_handler.go: runTunnel() extracted, tüm fonksiyonlar transport.Layer kullanıyor (Faz 2 obfuscation hazır)
- [x] test/integration/helpers_test.go: goleak TestMain — sıfır goroutine leak onaylandı
- [x] go.mod: go.uber.org/goleak v1.3.0 eklendi
- [x] git commit d99f3af (Oturum 1.19)
- [x] docs/PROTOCOL.md v1.1: §11 Transport Abstraction (Layer interface, optional capabilities, Faz 2 extension points), Changelog
- [x] pkg/relay/stats_handler.go: StatsHandler — JSON + Prometheus text exposition format
- [x] pkg/relay/stats_handler_test.go: 5 unit test (JSON, Prometheus via Accept/param, default, zero)
- [x] cmd/nabu-relay/main.go: --stats-addr flag, /metrics + /stats endpoints, graceful shutdown
- [x] git commit 55978f3 (Oturum 1.20)
- [x] pkg/transport/layer.go: SessionKeySetter interface eklendi (eksik tespit edildi)
- [x] pkg/obfuscation/http_connect.go: HTTPConnect — transport.Layer impl
  - TCP üzerinden 4-byte length-prefix frame (SendFrame/ReceiveFrame)
  - Opsiyonel HTTP CONNECT proxy (ProxyAddr boşsa direkt TCP)
  - SetReadTimeout + SetSessionKey interface desteği
  - Compile-time assertions (transport.Layer, ReadTimeoutSetter, SessionKeySetter)
- [x] pkg/obfuscation/crypto.go: pkg/crypto için ince yerel sarmalayıcılar
- [x] pkg/obfuscation/factory.go: NewLayer(mode, relayAddr, proxyAddr) — none|http-connect
- [x] pkg/obfuscation/*_test.go: 12 birim testi (8 HTTPConnect + 4 factory)
- [x] pkg/tunnel/relay_handler.go: NewRelayHandlerWithLayer() eklendi
  - NewRelayHandler() → thin wrapper (UDP fallback korundu)
  - layer!=nil ise pre-built layer kullanılır (obfuscation için)
- [x] cmd/nabu-client/main.go: --obfuscation ve --obfs-proxy flag'leri eklendi
- [x] Tüm testler geçti (go test -race ./...) — 8 paket + integration
- [x] golangci-lint clean
- [x] pkg/relay/tcp_server.go: TCPServer — HTTP CONNECT + length-prefix framing + X25519 DH + dispatch
  - AcceptHTTPConnect=true: HTTP CONNECT preamble okur relay-side
  - pipeTargetToClient: ctx-cancel ile goroutine temizleniyor
  - handleConnect: remote param kaldırıldı (unused)
- [x] cmd/nabu-relay/main.go: --serve-tcp, --tcp-addr, --tcp-http-connect flag'leri
  - UDP goroutine ile eş zamanlı TCP relay başlatılıyor
- [x] pkg/tunnel/relay_handler.go: NewRelayHandlerWithFactory() eklendi
  - Her SOCKS5 session'da yeni Layer yaratır (TCP layer'lar için doğru yaklaşım)
- [x] test/integration/helpers_test.go: dialSOCKS5() yardımcısı + socks5 import
- [x] test/integration/http_connect_relay_test.go: 2 yeni integration test
  - TestHTTPConnectRelayDirectEcho: HTTPConnect → TCPServer → echo (SOCKS5 yok)
  - TestHTTPConnectViaTCPRelaySOCKS5: tam SOCKS5 → HTTPConnect → TCPServer yolu
- [x] docs/PROTOCOL.md v1.2: §12 TCP Transport & HTTPConnect Obfuscation
- [x] Tüm testler geçti (go test -race ./...) — 9 paket 0 FAIL, goleak temiz
- [x] golangci-lint clean
- [x] git commit 34876f1 (Oturum 1.22)
- [x] pkg/relay/tls_config.go: BuildTLSConfig() — sertifika dosyası veya self-signed ECDSA P-256
  - MinVersion: TLS 1.3 (DPI parmak izi direnci)
  - generateSelfSigned(): CN=nabu-relay, 2 yıllık geçerlilik, her başlatılda yeni cert
- [x] pkg/relay/tcp_server.go: TLSConfig *tls.Config alanı + Start() içinde tls.NewListener wrap
  - "tls=true/false" log mesajına eklendi
- [x] cmd/nabu-relay/main.go: --tcp-tls, --tcp-cert, --tcp-key flag'leri
  - relay.BuildTLSConfig() çağrısı + tcpServer.TLSConfig set
- [x] pkg/relay/udp_server.go: StreamState.BytesIn + BytesOut (atomic.Int64)
  - Per-stream byte sayacı — GlobalStats'a ek olarak
- [x] pkg/relay/tcp_server.go: handleData + pipeTargetToClient state.BytesIn/BytesOut günceller
- [x] pkg/obfuscation/http_connect.go: WrapConn() + NewRawTCPLayer() helpers
  - Hazır net.Conn'u transport.Layer olarak sarar (TLS conn için)
- [x] test/integration/http_connect_relay_test.go: TestTLSTCPRelayDirectEcho eklendi
  - tls.Dial + NewRawTCPLayer + CONNECT/DATA/echo round-trip PASS
- [x] docs/PROTOCOL.md v1.3: §13 TLS Wrapping bölümü
  - Motivasyon, mimari, self-signed cert, per-stream sayıçlar
- [x] Tüm testler geçti (go test -race ./...) — 9 paket 0 FAIL
- [x] golangci-lint clean
- [x] git commit 06a88be (Oturum 1.23)
- [x] pkg/relay/replay_window.go: ReplayWindow — 64-frame bitmap sliding window (NewReplayWindow, Check, Reset)
- [x] pkg/relay/replay_window_test.go: 8 unit test (FirstFrame/Duplicate/OldRejected/OOO/Boundary/LargeJump/Sequential/Reset) PASS
- [x] pkg/relay/tcp_server.go: handleConn'da per-connection anti-replay (replay := NewReplayWindow())
- [x] pkg/relay/udp_server.go: replayWindows sync.Map + getOrCreateReplayWindow/resetReplayWindow + Start() loop anti-replay check
- [x] pkg/obfuscation/http_connect.go: RelayTLSConfig *tls.Config alanı + Connect() TLS upgrade (tls.Client + explicit Handshake + SNI)
- [x] cmd/nabu-client/main.go: --obfs-tls + --obfs-tls-insecure flag'leri; HTTPConnect.RelayTLSConfig set
- [x] test/integration: TestTCPRelayReplayDrop + TestHTTPConnectClientTLSDial PASS
- [x] docs/PROTOCOL.md v1.4: §14 Anti-replay Window (motivasyon, bitmap algoritması, kural tablosu, kapsam, changelog)
- [x] Tüm testler geçti (go test -race ./...) — 9 paket 0 FAIL, goleak temiz
- [x] golangci-lint clean
- [x] git commit b66c68d (Oturum 1.24)
- [x] pkg/obfuscation/websocket.go: WebSocketLayer (RFC 6455 framing, FIN/mask, server-mode AcceptConn)
- [x] pkg/relay/tcp_server.go: AcceptWebSocket flag + handleConn WS handshake path
- [x] cmd/nabu-relay/main.go: --serve-ws / --ws-addr flags
- [x] test/integration: TestWebSocketRelayDirectEcho PASS
- [x] docs/PROTOCOL.md v1.5: §15 WebSocket Obfuscation
- [x] git commit 38fd74d (Oturum 1.25)
- [x] pkg/obfuscation/utls_dialer.go: UTLSDial() + ParseUTLSFingerprint() (chrome/firefox/safari/edge/golang/random)
- [x] pkg/obfuscation/http_connect.go: UTLSEnabled bool + UTLSFingerprint string alanları
- [x] pkg/obfuscation/websocket.go: UTLSEnabled bool + UTLSFingerprint string alanları
- [x] cmd/nabu-client/main.go: --obfs-utls + --obfs-utls-fingerprint flags
- [x] pkg/obfuscation/utls_dialer_test.go: 6 unit test (parse/chrome/firefox/unknown/ws-flag/hc-flag) PASS
- [x] git commit 77115bf (Oturum 1.26)
- [x] pkg/crypto/salamander.go: SalamanderEncode/Decode, HKDF-SHA256 per-frame key, AES-256-GCM envelope (overhead=36B)
- [x] pkg/crypto/salamander_test.go: 7 unit test (RoundTrip/NonDet/WrongPSK/ShortPacket/EmptyPSK/EmptyPayload/Tampered) PASS
- [x] pkg/transport/udp_client.go: SalamanderPSK field; SendFrame encode / ReceiveFrame decode + MeasureRTT Salamander bug fix
- [x] pkg/relay/udp_server.go: SalamanderPSK field; decode ReadFrom loop; encode sendFrame+sendHandshakeACK
- [x] pkg/tunnel/relay_handler.go: NewRelayHandlerUDPSalamander(relayAddr, psk, salamanderPSK)
- [x] cmd/nabu-client/main.go: --salamander-psk flag
- [x] cmd/nabu-relay/main.go: --salamander-psk flag
- [x] test/integration: TestSalamanderUDPEcho + TestSalamanderWrongPSKRejected PASS
- [x] docs/PROTOCOL.md v1.6: §16 Salamander UDP Obfuscation
- [x] Tüm testler geçti (go test -race ./...) — 9 paket 0 FAIL
- [x] golangci-lint clean
- [x] git commit 95096f0 (Oturum 1.27)

## Yarım Kalanlar
- Probe defense (gerçek HTTP camouflage + IP ban) → Oturum 1.28
- Connection multiplexing (multiple streams over one TLS session)
- QUIC/HTTP3 maskeleme (Sprint 9)

## Açık Sorular / Blokerlar
- Varsayilan relay portu kesinlesti: UDP/443
- Ilk demo relay lokasyonu kesinlesti: OCI Marseille (fr-mrs-1)
- Konfig modeli kesinlesti: hybrid (dosya + CLI override)
- Repo aktif: https://github.com/TuncayASMA/nabu

## Notlar
- RUNBOOK.md tüm 5 fazı, tüm sprint ve oturumları içeriyor
- Her oturum 4-5 saat max — 3 saatte uyarı ver
- tdd-guide agent: her yeni modülde önce test yaz
- security-reviewer: kripto ve network kodu için ZORUNLU
- Relay artik private/link-local hedefleri varsayilan olarak blokluyor; integration testler AllowPrivateTargets=true ile calisiyor

## Bağımlılık Durumu
 - Go: ✅ go1.26.1 linux/arm64 — /usr/local/go/bin/go
- Rust: ❌ Faz 4'te gerekli, şimdilik opsiyonel
- nDPI: ❌ Faz 1 sonu DPI testleri için gerekli
- Docker: ✅ Docker 29.1.5 kurulu
- GitHub remote: ✅ origin -> https://github.com/TuncayASMA/nabu.git
