# NABU — SESSION STATE
# Bu dosyayı her oturum başında oku, her oturum sonunda güncelle.

## Son Güncelleme
Tarih: 2026-04-09
Oturum: 1.26 (Tamamlandı)

## Mevcut Faz / Sprint / Oturum
- Faz: 2 — QUIC Maskeleme + Obfuscation Layer
- Sprint: 8 — TCP/HTTPConnect/TLS/WebSocket/uTLS Obfuscation
  - ✅ HTTPConnect obfuscation layer (Oturum 1.21-1.22)
  - ✅ TCPServer TLS wrapping (Oturum 1.23)
  - ✅ Anti-replay window + client TLS dialer (Oturum 1.24)
  - ✅ WebSocket obfuscation RFC 6455 (Oturum 1.25)
  - ✅ uTLS Chrome/Firefox/Edge fingerprint (Oturum 1.26)
  - 🔜 Salamander UDP obfuscation (Oturum 1.27)
- Oturum: 1.26 → Sonraki: 1.27 (Salamander UDP obfuscation)

## Bir Sonraki Oturum İlk Görevi
```
Oturum 1.27 — Salamander UDP obfuscation:
1. pkg/obfuscation/salamander.go: SalamanderConn — UDP üzerinde
   [8B random salt][AES-GCM şifreli payload] — her frame farklı salt
   transport.Layer interface impl (SendFrame/ReceiveFrame)
2. pkg/obfuscation/salamander_test.go: 5+ unit test
3. pkg/relay/udp_server.go: SalamanderMode bool — gelen UDP frame
   salt+decrypt logic ekle (opsiyonel mod)
4. cmd/nabu-client: --obfuscation=salamander desteği
5. test/integration: TestSalamanderUDPEcho
6. PROTOCOL.md v1.6: §16 Salamander UDP Obfuscation
```

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

## Yarım Kalanlar
- Salamander UDP obfuscation (salt+AES-GCM per-frame) → Oturum 1.27
- Connection multiplexing (multiple streams over one TLS session)
- Probe defense (gerçek HTTP/3 camouflage) → Sprint 8.4

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
