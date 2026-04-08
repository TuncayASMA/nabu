# NABU — SESSION STATE
# Bu dosyayı her oturum başında oku, her oturum sonunda güncelle.

## Son Güncelleme
Tarih: 2026-04-08
Oturum: 1.11 (Tamamlandı)

## Mevcut Faz / Sprint / Oturum
- Faz: 1 — Temel UDP Tünel
- Sprint: 1 — Proje Bootstrap
- Oturum: 1.11 — X25519 ephemeral key exchange + PSK auth reject

## Bir Sonraki Oturum İlk Görevi
```
1. pkg/relay: per-source rate limiting (token bucket, UDP kaynak IP başına, ~100 pkt/s)
2. pkg/transport: RTT-aware congestion backoff (ping/pong frame veya frame timestamp)
3. deploy/: Docker Compose (client+relay) + OCI ARM systemd deployment rehberi
4. pkg/relay: bant genişliği istatistikleri (bytes_in/out per stream, prometheus gauge opsiyonel)
5. docs/PROTOCOL.md: wire format, handshake akışı, şifreleme katmanı dokümantasyonu
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

## Yarım Kalanlar
- Rate limiting ve per-source quota henüz yok
- RTT-aware congestion backoff henüz yok
- Deployment dökümantasyonu henüz yok
- Protocol wire format dokümantasyonu (PROTOCOL.md) yok

## Reliability Notu (1.9)
- Stop-and-wait ACK: tamamlandı
- Reorder buffer (OOO + duplicate): tamamlandı, integration testleri geçiyor
- Backpressure (max 64 frame/stream): tamamlandı
- Exponential backoff (300ms → 4s): tamamlandı

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
