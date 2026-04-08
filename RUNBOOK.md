# NABU — Tam Geliştirme Runbook'u
> UDP Tabanlı Anti-DPI Sızma Sistemi | Özgür İnternet Projesi
> Sürüm: 1.0 | Nisan 2026 | Hazırlayan: Tuncay Aşma

---

## ⚙️ OTURUM PROTOKOLÜ (HER GÜN UYGULANACAK)

### Oturum Başlangıcı (ilk 15 dk)
```
1. /home/ubuntu/nabu/SESSION_STATE.md oku
2. /memories/repo/nabu-project.md oku
3. Git log --oneline -10 ile son durumu gör
4. Günün hedefini tek cümleyle yaz SESSION_STATE'e
5. "NABU projesine devam ediyoruz, SESSION_STATE.md'yi oku" de
```

### ⏰ Oturum Zaman Kuralları
| Süre | Eylem |
|------|-------|
| 0–30 dk | Durum inceleme + planlama |
| 30 dk – 3 saat | Derin kodlama |
| **3 saat** | ⚠️ **UYARI: Context şişiyor. Mevcut modülü tamamla, commit at.** |
| 3–4 saat | Test yaz, review yap |
| **4 saat** | 🔴 **DUR: Commit + SESSION_STATE güncelle + plan yaz** |
| **4.5 saat** | 🚨 **ZORUNLU DURUŞ. Devam etme.** |

### Oturum Kapanışı (son 30 dk)
```
1. git add -A && git commit -m "feat/fix/test: <açıklama>"
2. SESSION_STATE.md'yi güncelle:
   - Tamamlananlar
   - Yarım kalanlar (satır numarasıyla)
   - Sonraki oturum ilk görevi
   - Açık sorular / blokerlar
3. Yeni sohbet için not: "Bir sonraki oturumda SESSION_STATE.md'yi oku"
```

---

## 🤖 AI ARAÇ & AJAN ATAMASI

### Hangi iş için hangi araç?

| Görev | Araç / Ajan |
|-------|-------------|
| Go kod yazma | **golang-pro** agent |
| Rust kod yazma | **rust-pro** agent |
| Test yazma (TDD) | **tdd-guide** agent |
| Güvenlik review (kripto, auth) | **security-reviewer** agent |
| Genel kod review | **code-reviewer** agent |
| Build/derleme hatası | **build-error-resolver** agent |
| Performans optimizasyon | **performance-optimizer** agent |
| Mimari karar | **architect** agent |
| Docker/deployment | **devops-engineer** agent |
| Benchmark/profil analizi | **data-analyst** agent |
| Hata ayıklama | **debugger** agent |

### Zorunlu Review Kuralları
- **Her yeni modül sonrası:** `code-reviewer` + `security-reviewer` (kripto/network kodu için)
- **Her Faz sonrası:** `architect-review` ile mimari bütünlük kontrolü
- **Rust kodu:** `rust-reviewer` zorunlu
- **Build kırılırsa:** İlk `build-error-resolver`, sonra devam

---

## 📁 PROJE YAPISI

```
nabu/
├── cmd/
│   ├── nabu-client/        # İstemci binary giriş noktası
│   │   └── main.go
│   └── nabu-relay/         # Relay sunucu binary
│       └── main.go
├── pkg/
│   ├── socks5/             # SOCKS5 proxy sunucu
│   ├── crypto/             # AES-256-GCM / XChaCha20 şifreleme
│   ├── fec/                # Reed-Solomon FEC
│   ├── transport/          # Ham UDP taşıma, pencere, yeniden gönderim
│   ├── relay/              # Relay sunucu mantığı
│   ├── phantom/            # Micro-Phantom örtü trafik motoru
│   │   ├── profiles/       # PCAP'tan türetilen tarayıcı profilleri
│   │   ├── shaper/         # Trafik şekillendirici
│   │   └── firstpacket/    # İlk paket entropi optimizasyonu
│   ├── governor/           # Bağlam-duyarlı yönetici (eBPF)
│   ├── multipath/          # Çok yollu QUIC zamanlayıcılar
│   ├── p2p/                # P2P Smoke Screen (libp2p)
│   └── tui/                # Bubbletea terminal panosu
├── deploy/
│   ├── terraform/          # OCI + Hetzner relay provisioning
│   └── docker/             # Docker Compose relay deploy
├── test/
│   ├── unit/               # Her pkg için birim testler
│   ├── integration/        # Modüller arası entegrasyon
│   ├── dpi/                # nDPI + Suricata otomatik test
│   ├── e2e/                # Uçtan uca tünel testi
│   └── benchmark/          # Performans kıyaslama
├── tools/
│   ├── pcap-analyzer/      # PCAP → phantom profili çıkarıcı
│   └── dpi-tester/         # Yerel DPI test koşucusu
├── .github/
│   └── workflows/
│       ├── ci.yml          # Build + test
│       ├── dpi-test.yml    # DPI direnç testi
│       └── release.yml     # Binary release
├── docs/
│   └── research/           # Akademik referanslar, notlar
├── go.mod
├── go.sum
├── Makefile
├── README.md
└── LICENSE                 # AGPL-3.0
```

---

## 🗺️ FAZ BAZLI OTURUM PLANI

---

# FAZ 1 — Temel UDP Tünel (Ay 1–2, ~40 oturum)

**Hedef:** Çalışan PoC — SOCKS5 → AES-256-GCM → FEC → UDP → OCI Relay

**Referans:** Hysteria2 fork'u base olarak al, sonra modülleri yeniden yaz

## Sprint 1 — Proje Bootstrap (Hafta 1, 5 oturum)

### Oturum 1.1 — GitHub + Go Modül Kurulumu
**Hedef:** Çalışan Go ortamı, GitHub repo, temel CI
```bash
Adımlar:
1. git init, GitHub repo oluştur (nabu)
2. go mod init github.com/nabu-tunnel/nabu
3. Temel klasör yapısını oluştur
4. .github/workflows/ci.yml — go test ./... + go vet
5. Makefile hedefleri: build, test, lint, clean
6. LICENSE (AGPL-3.0) + README.md iskeleti
7. .gitignore (Go standard)
8. pre-commit hook: go fmt, go vet
```
**Araç:** golang-pro agent
**Test:** `go build ./...` başarılı
**Commit:** `chore: initial project structure`

### Oturum 1.2 — Hysteria2 Kaynak Analizi
**Hedef:** Fork stratejisi kararı, alınacak modülleri belirle
```bash
Adımlar:
1. github.com/apernet/hysteria klonla (referans olarak)
2. pkg/transport, pkg/utils, app/internal/protocol incele
3. Hangi kodu doğrudan alacağız, hangisini yeniden yazacağız? → SESSION_STATE'e yaz
4. Lisans uyumluluğu kontrol: MIT → AGPL-3.0 uyumlu ✓
5. go.mod bağımlılıklarını incele, Nabu'a eklenecekleri listele
```
**Araç:** Ben (analiz), architect agent (mimari karar)
**Çıktı:** SESSION_STATE'e "Hysteria2'den alınacaklar" bölümü

### Oturum 1.3 — go.mod + Bağımlılıklar
**Hedef:** Tüm Phase 1 bağımlılıklarını ekle, doğrula
```go
// go.mod bağımlılıkları
require (
    github.com/things-go/go-socks5 v0.0.4
    github.com/klauspost/reedsolomon v1.12.1
    golang.org/x/crypto v0.22.0
    github.com/spf13/viper v1.19.0
    github.com/rs/zerolog v1.33.0
    github.com/prometheus/client_golang v1.19.0
    github.com/klauspost/cpuid/v2 v2.2.7
    github.com/stretchr/testify v1.9.0  // test
    github.com/ory/dockertest/v3 v3.10.0 // entegrasyon test
)
```
**Test:** `go mod tidy` hatasız
**Commit:** `chore: add phase 1 dependencies`

### Oturum 1.4 — Makefile + Dev Toolchain
```makefile
# Hedefler:
build:         # nabu-client + nabu-relay binary
test:          # go test -race ./...
test-cover:    # > %80 coverage zorunlu
lint:          # golangci-lint run
bench:         # go test -bench=. ./pkg/...
dpi-test:      # Docker'da nDPI testi
relay-up:      # Docker Compose relay başlat
relay-down:    # Relay durdur
fmt:          # gofmt + goimports
```
**Araç:** bash-pro agent (Makefile)

### Oturum 1.5 — golangci-lint Konfigürasyonu
```yaml
# .golangci.yml — etkin linter'lar:
# errcheck, gosimple, govet, ineffassign, staticcheck
# gosec (güvenlik), exhaustive, gocritic, revive
```

---

## Sprint 2 — Şifreleme Katmanı (Hafta 2, 5 oturum)

### Oturum 2.1 — pkg/crypto Tasarım + TDD
**Araç:** tdd-guide agent (önce test yaz!)
```go
// Önce test yaz:
// TestAESGCMEncryptDecrypt
// TestXChaChaEncryptDecrypt
// TestHKDFKeyDerivation
// TestNonceUniqueness
// TestARMDetection
// BenchmarkAESGCM_1KB, BenchmarkAESGCM_1MB
// BenchmarkXChaCha20_1KB, BenchmarkXChaCha20_1MB
```

### Oturum 2.2 — AES-256-GCM Implementasyonu
```go
// pkg/crypto/aes_gcm.go
// - ARM64 AES uzantı tespiti (cpuid)
// - HKDF-SHA256 ile PSK → session key türetimi
// - Her paket benzersiz nonce (atomic counter + random salt)
// - Paket formatı: [12B nonce][şifreli yük][16B GCM tag]
```
**Araç:** golang-pro agent
**Güvenlik Review:** security-reviewer agent (ZORUNLU — kripto kodu)

### Oturum 2.3 — XChaCha20-Poly1305 Fallback
```go
// pkg/crypto/chacha20.go
// - Fallback: ARM AES uzantısı yoksa
// - 24B nonce (XChaCha20 standardı)
// - Aynı interface: Encrypt(plaintext, key) (ciphertext, error)
```

### Oturum 2.4 — Runtime Algılama + Interface
```go
// pkg/crypto/cipher.go
// Cipher interface:
type Cipher interface {
    Encrypt(plaintext []byte) ([]byte, error)
    Decrypt(ciphertext []byte) ([]byte, error)
    KeySize() int
    Overhead() int
}
// New(psk []byte) Cipher — CPU'ya göre otomatik seç
```

### Oturum 2.5 — Bellek Güvenliği + Testler Tamamlama
```go
// - PSK kullanım sonrası zeroise (runtime.SetFinalizer + explicit)
// - Hassas veri loglanmaması (zerolog hook)
// - Tüm testler geçmeli: go test -race ./pkg/crypto/...
// - Coverage > %85
```
**Review:** code-reviewer + security-reviewer

---

## Sprint 3 — FEC Katmanı (Hafta 3, 4 oturum)

### Oturum 3.1 — pkg/fec TDD
```go
// Önce testler:
// TestReedSolomonEncode10_3
// TestReedSolomonRecoverFrom3Lost
// TestFECOverhead (< %32)
// BenchmarkFECEncode_1KB, BenchmarkFECEncode_64KB
// TestCodecWarmup (ön-ısınma gerekliliğini doğrula)
```
**Araç:** tdd-guide agent

### Oturum 3.2 — Reed-Solomon Implementasyonu
```go
// pkg/fec/codec.go
// - klauspost/reedsolomon v1.12+ (ARM64 NEON optimize)
// - 10 veri + 3 parite = 13 shard
// - Her şartta bağımsız şifreleme
// - sync.Pool ile shard tampon havuzu
// - Ön-ısınma: init() ile goroutine başlat
```
**Araç:** golang-pro agent

### Oturum 3.3 — Paket Gruplama + Zamanlama
```go
// pkg/fec/grouper.go
// - N paket grupla → FEC kodla → gönder
// - Adaptif grup boyutu (latency vs overhead trade-off)
// - Timeout: tüm grup dolmasa da gönder (50ms max)
```

### Oturum 3.4 — FEC Testler + Benchmark
```go
// - Paket kaybı simülatörü yaz (test helper)
// - %1, %3, %5, %10 kayıp oranında recovery testi
// - ARM64'te benchmark: > 500 MB/s hedef
// - Coverage > %85
```
**Review:** code-reviewer

---

## Sprint 4 — UDP Transport (Hafta 4–5, 6 oturum)

### Oturum 4.1 — pkg/transport Tasarım + TDD
```go
// Testler önce:
// TestPacketSequencing
// TestSlidingWindowReassembly
// TestDuplicateDetection
// TestRetransmissionTimeout
// TestMTUSafety (> 1350B paket parçalanmalı)
// BenchmarkUDPThroughput (> 200 Mbps loopback)
```

### Oturum 4.2 — Paket Formatı
```go
// pkg/transport/packet.go
// Format: [2B seq_num][1B flags][4B timestamp][şifreli yük][4B CRC32]
// Flags: DATA=0x01, ACK=0x02, FIN=0x04, KEEPALIVE=0x08
// sync.Pool ile tampon ayırma
// MTU-safe: max 1350 byte payload
```

### Oturum 4.3 — Kayan Pencere + Yeniden Gönderim
```go
// pkg/transport/window.go
// - Kayan pencere (window size: 256 paket)
// - RTO: adaptif (SRTT + 4*RTTVAR, RFC 6298)
// - Zaman aşımı tabanlı yeniden gönderim (max 3 deneme)
// - Çift tespit: BitSet ile
```

### Oturum 4.4 — UDP Soket Yönetimi
```go
// pkg/transport/conn.go
// - Soket tamponları: 4MB (SO_RCVBUF/SO_SNDBUF)
// - GSO/GRO desteği (Linux 5.4+ için)
// - Çok çekirdekli okuma: N goroutine (GOMAXPROCS)
```

### Oturum 4.5 — Transport Entegrasyon Testi
```go
// test/integration/transport_test.go
// - Gerçek UDP loopback testi
// - %5 yapay paket kaybıyla tünel testi
// - 50 Mbps+ throughput doğrulama
// - dockertest ile izole ortam
```

### Oturum 4.6 — Performans Optimizasyon
**Araç:** performance-optimizer agent
```
- go tool pprof ile CPU profili
- heapescape analizi (//go:noescape)
- sync.Pool düzgün kullanım kontrolü
- Gereksiz allocation tespiti
```

---

## Sprint 5 — SOCKS5 Proxy (Hafta 6, 3 oturum)

### Oturum 5.1 — pkg/socks5 TDD
```go
// Testler:
// TestSOCKS5Connect_TCP
// TestSOCKS5UDPAssociate
// TestSOCKS5AuthBypass (no-auth mode)
// TestSOCKS5LocalhostOnly (güvenlik: sadece 127.0.0.1)
// TestSOCKS5MaxConnections
```
**Araç:** tdd-guide agent

### Oturum 5.2 — SOCKS5 Implementasyonu
```go
// pkg/socks5/server.go
// - things-go/go-socks5 ile
// - CONNECT + UDP ASSOCIATE
// - Custom dialer: tünel üzerinden yönlendir
// - Max bağlantı limiti (default: 100)
// - Sadece localhost bağlantısı kabul et
```
**Araç:** golang-pro agent
**Güvenlik Review:** security-reviewer (ZORUNLU)

### Oturum 5.3 — SOCKS5 + Transport Entegrasyon
```go
// test/integration/socks5_tunnel_test.go
// SOCKS5 → Transport → (mock relay) uçtan uca
// curl --socks5 127.0.0.1:1080 http://example.com (e2e)
```

---

## Sprint 6 — Relay Sunucu (Hafta 7, 4 oturum)

### Oturum 6.1 — pkg/relay TDD
```go
// Testler:
// TestRelayPacketForwarding
// TestSessionManagement
// TestConcurrentSessions (100 eş zamanlı)
// TestRelayMemoryLeak (pprof heap)
// BenchmarkRelay_10kPPS
```

### Oturum 6.2 — Relay Implementasyonu
```go
// pkg/relay/server.go
// - UDP paket al → crypto çöz → FEC birleştir → hedef ilet
// - Her istemci oturumu: sync.Map ile takip
// - Oturum zaman aşımı + temizleme goroutine
// - Prometheus metrikleri: aktif oturum, throughput, hata sayısı
```

### Oturum 6.3 — Relay Konfigürasyon + Systemd
```yaml
# deploy/docker/relay.docker-compose.yml
# - OCI ARM uyumlu
# - Prometheus scrape endpoint
# - Graceful shutdown (SIGTERM)
```
**Araç:** devops-engineer agent (Docker/systemd)

### Oturum 6.4 — Faz 1 E2E Test
```bash
# test/e2e/phase1_test.sh
# 1. Docker'da relay başlat
# 2. Yerel client bağlan
# 3. curl --socks5 ile gerçek HTTP isteği at
# 4. throughput ölç (iperf3)
# 5. nDPI ile trafik analiz et → "Unknown" olmalı
```

---

## Sprint 7 — Faz 1 Sağlamlaştırma (Hafta 8, 3 oturum)

### Oturum 7.1 — cmd/ Binary'leri
```go
// cmd/nabu-client/main.go
// - Viper YAML config
// - Graceful shutdown (SIGINT/SIGTERM)
// - Zerolog JSON logging (hassas veri filtreleme)
// - --version, --config flags

// cmd/nabu-relay/main.go
// - Aynı pattern
// - --listen-addr, --upstream flags
```

### Oturum 7.2 — CI/CD Pipeline
```yaml
# .github/workflows/ci.yml
# - go test -race ./...
# - golangci-lint
# - coverage check (> %80)
# - go build linux/amd64 + linux/arm64
# - Docker image build + push
```
**Araç:** devops-engineer agent

### Oturum 7.3 — Faz 1 Mimari Review
**Araç:** architect-review agent (ZORUNLU)
```
Kontrol listesi:
✓ Her modül bağımsız test edilebilir mi?
✓ Interface'ler doğru tasarlanmış mı?
✓ Goroutine leak var mı? (goleak ile)
✓ Error handling tutarlı mı?
✓ Faz 2 için hazır mı?
```

---

# FAZ 2 — QUIC Maskeleme + Micro-Phantom (Ay 3–5, ~50 oturum)

## Sprint 8–9 — QUIC/HTTP3 Maskeleme (2 hafta)

### Oturum 8.1 — quic-go Entegrasyonu
```go
// go get github.com/quic-go/quic-go@v0.43.0
// pkg/quic/server.go — HTTP/3 sunucu (relay tarafı)
// pkg/quic/client.go — HTTP/3 istemci
// Let's Encrypt TLS (autoTLS)
// Kimlik doğrulanmamış GET / → gerçek web içeriği döndür
// POST /auth → HMAC-SHA256 PSK token doğrula → tünel modu
```
**Araç:** golang-pro agent

### Oturum 8.2 — uTLS Chrome Fingerprint Taklidi
```go
// go get github.com/refraction-networking/utls
// pkg/quic/fingerprint.go
// - utls.HelloChrome_Auto
// - GREASE uzantıları
// - ECH uzantısı normalleştirme
// KRİTİK: JA3/JA4 + User-Agent + HTTP/2 SETTINGS tutarlı olmalı
```
**Güvenlik Review:** security-reviewer (ZORUNLU — parmak izi tutarlılığı)

### Oturum 8.3 — Salamander Fallback Modu
```go
// pkg/quic/salamander.go
// - QUIC engelleme tespiti
// - [8B random salt][XOR-obfuscated payload]
// - Otomatik mod geçişi
```

### Oturum 8.4 — Aktif Prob Savunması
```go
// pkg/relay/probe_defense.go
// - Kimlik doğrulamasız bağlantıya gerçek web içeriği sun
// - nginx veya Go HTTP/3 sunucu: gerçek bir blog/portfolio
// - Prob tespit: olağandışı tarama deseni → rate limit
```

### Oturum 8.5–8.6 — QUIC Testler
```go
// - JA3 fingerprint doğrulama (ja3 kütüphanesi ile)
// - nDPI: "QUIC"/"HTTPS" olarak sınıflandırılmalı
// - Suricata sızma tespit: sıfır uyarı
// - Throughput: maskeleme sonrası > 40 Mbps
```

## Sprint 10–13 — Micro-Phantom Motoru (4 hafta)

### Oturum 10.1 — PCAP Analiz Aracı
```go
// tools/pcap-analyzer/main.go
// - Gerçek tarayıcı PCAP'larını analiz et
// - İstatistiksel profil çıkar:
//   * paket boyut dağılımı (histogram)
//   * paketler arası zaman (IAT) dağılımı
//   * patlama deseni
//   * oturum süresi
// - JSON profile çıkar → pkg/phantom/profiles/
// Kullanılacak PCAP'lar: Chrome web gezinme, YouTube, Twitter, Instagram
```
**Araç:** golang-pro + data-analyst agent (istatistik)

### Oturum 10.2–10.4 — Profil Kütüphanesi
```go
// pkg/phantom/profiles/
// ├── web_browsing.json    — Chrome genel gezinme
// ├── youtube_sd.json      — YouTube 720p
// ├── youtube_hd.json      — YouTube 1080p
// ├── instagram_feed.json  — Instagram kaydırma
// └── twitter_feed.json    — Twitter/X akışı

// Her profil:
type TrafficProfile struct {
    Name           string
    PacketSizeDist []float64  // CDF
    IATDist        []float64  // ms cinsinden IAT CDF
    BurstPattern   BurstModel
    SessionDuration Distribution
    DNSPatterns    []string
}
```

### Oturum 11.1–11.3 — Trafik Şekillendirici
```go
// pkg/phantom/shaper/shaper.go
// - Gerçek tünel trafiğini profile uyacak şekilde şekillendir
// - Paketleri profil dağılımından çekilen boyuta doldur (padding)
// - Boşta kalma: sentetik HTTPS paketleri üret (boş tünel trafik)
// - token bucket rate limiter (golang.org/x/time/rate)
// - Profil runtime'da değiştirilebilir
```

### Oturum 11.4–12.2 — Governor İlk Versiyon (basit)
```go
// pkg/governor/governor.go (Faz 2 versiyonu — eBPF olmadan)
// - Sistem ağ istatistikleri: /proc/net/dev
// - Mevcut tünel throughput
// - Günün saati katsayısı
// - Hedef: örten trafik oranını ayarla
// eBPF Faz 3'te gelecek
```

### Oturum 12.3–13.2 — Phantom Testler
```go
// test/dpi/phantom_test.go
// KS-testi: Nabu ve gerçek tarayıcı dağılımları p > 0.05
// nDPI sınıflandırma: "HTTPS" veya "QUIC"
// Suricata: sıfır uyarı (24 saatlik trafik)
// İlk paket entropi: Shannon < 7.2 (tipik HTTPS)
```
**Araç:** data-analyst agent (istatistiksel testler)

---

# FAZ 3 — Çok Yollu Relay + eBPF Governor (Ay 6–8, ~40 oturum)

## Sprint 14–16 — Çok Yollu QUIC (3 hafta)

### Oturum 14.1 — mp-quic-go Fork/Entegrasyon
```go
// github.com/project-faster/mp-quic-go veya
// quic-go multipath extension incelemesi
// pkg/multipath/scheduler.go

// Yol zamanlayıcıları:
// - MinRTT (varsayılan)
// - BLEST (HoL engelleme tahminli)
// - Redundant (kritik paketler için)
```

### Oturum 14.2–14.4 — Relay Ağı Konfigürasyonu
```
Topoloji:
İstemci → [OCI FR relay] + [Hetzner DE relay] → OCI DE çıkış relay → İnternet

OCI: Fransa (Marsilya) + İngiltere (Londra) örnekleri
Hetzner: Falkenstein (€4/ay ARM) — OCI yedeği
```

### Oturum 15.1–15.3 — Terraform ile Relay Provisioning
```hcl
// deploy/terraform/
// ├── oci/           — OCI ARM instance
// ├── hetzner/       — Hetzner Cloud ARM
// └── modules/
//     └── nabu-relay/  — ortak relay modülü
// Çıktı: relay IP'leri + otomatik nabu config
```
**Araç:** terraform-specialist agent

## Sprint 17–18 — eBPF Governor (2 hafta)

### Oturum 17.1–17.3 — eBPF Kernel Program
```c
// pkg/governor/ebpf/monitor.c
// - TC (traffic control) hook
// - Ağ arayüzü başına: paket sayısı, byte sayısı, IAT
// - ring buffer ile user-space'e event akışı
// cilium/ebpf ile Go wrapper
```
**Araç:** golang-pro agent (eBPF/Go)

### Oturum 17.4–18.2 — Governor Karar Motoru
```go
// pkg/governor/governor.go
// Her 100ms karar döngüsü:
// input: eBPF metrikleri + tünel stats + saat
// output:
//   - phantomRate: float64 (0.0-1.0)
//   - schedulerBias: yol tercihi
//   - fecRatio: redundans oranı
//   - burstMode: bool

// Adaptif algoritma:
// - Düşük gerçek trafik → yüksek phantom trafik
// - Yüksek FEC kaybı = olası kısıtlama → alarm
```

## Sprint 19–20 — DNS + Network Stack (2 hafta)

### Oturum 19.1–19.2 — DNS Sızıntı Önleme
```go
// ⚡ SHORTCUT: Sıfırdan yazmak YOK!
// github.com/labyrinthdns/labyrinth kullan (MIT, Pure Go)
// - DoH + DoH/3 (HTTP/3) + DoT + DNSSEC tam desteği
// - 22M cache reads/sec, 45ns latency
// - Prometheus metrics dahili
// - Ersin Koç tarafından geliştirilmiş, aktif geliştirme

// pkg/dns/client.go — Labyrinth embedded veya sidecar
// - Labyrinth'i SOCKS5 tüneli üzerinden route et
// - iptables kuralları: UDP/53 DROP (yerel sızıntı önleme)
// - IPv6 devre dışı (tünellenmiyorsa)
// - Labyrinth'in blocklist özelliği: reklam + tracker engelleyici bonus

// deploy/docker/dns.docker-compose.yml — Labyrinth sidecar
```

### Oturum 19.3 — DNS Sızıntı Testleri
```bash
# dnsleaktest.com API ile otomatik test
# test/e2e/dns_leak_test.sh
# - tünel açık: sıfır sızıntı
# - tünel kapalı: normal davranış
```

### Oturum 19.4–20.2 — Faz 3 E2E + Performans
```
- 3 relay üzerinden uçtan uca gecikme < 150ms (Avrupa)
- Tek relay arızası < 500ms kurtarma
- Governor 24 saatlik p > 0.05 trafik profili
- DNS sızıntı testi: sıfır
```

---

# FAZ 4 — P2P Smoke Screen + Üretim (Ay 9–12, ~50 oturum)

## Sprint 21–22 — P2P Relay Ağı (2 hafta)

### Oturum 21.1–21.3 — libp2p Bootstrap
```go
// go get github.com/libp2p/go-libp2p
// pkg/p2p/node.go
// - Relay keşif protokolü
// - PSK tabanlı özel ağ (yabancı node giremesin)
// - Firebase Cloud Messaging → engellemeye dayanıklı bootstrap
// - Telegram bot fallback (CenPush yaklaşımı)
```

### Oturum 21.4–22.2 — Smoke Screen
```go
// pkg/p2p/smokescreen.go
// - Eşler arası SADECE cover trafik taşı (gerçek yük asla)
// - Plausible deniability: "sadece QUIC trafiği"
// - Merkezi relay başarısız → P2P devreye gir
```

## Sprint 23–25 — Rust Migrasyonu (3 hafta)

### Oturum 23.1–23.3 — Rust Kripto Modülü
```rust
// rust/crypto/src/lib.rs
// - ring crate: AES-256-GCM + XChaCha20-Poly1305
// - Açık SIMD (AVX2/ARM NEON) optimize
// - #[no_mangle] extern "C" fonksiyonlar
// - CGo ile Go bağlama
```
**Araç:** rust-pro agent
**Review:** rust-reviewer agent (ZORUNLU)

### Oturum 24.1–24.3 — Rust FEC Modülü
```rust
// rust/fec/src/lib.rs
// - reed-solomon-erasure crate
// - AVX2/NEON SIMD
// - Beklenen: 2-3x throughput artışı
```

### Oturum 25.1–25.2 — Rust Benchmark
```
- cargo bench
- Go vs Rust karşılaştırma: hyperfine
- Hedef: kripto 2x+, FEC 2-3x
```
**Araç:** performance-optimizer agent

## Sprint 26–27 — TUI Pano (2 hafta)

### Oturum 26.1–26.2 — Bubbletea TUI
```go
// pkg/tui/dashboard.go
// Ekranlar:
// ┌─ NABU Dashboard ─────────────────────────────────┐
// │ Durum: ● BAĞLI    Relay: OCI-FR + HZ-DE          │
// │ Throughput: ↑ 12.3 Mbps  ↓ 8.1 Mbps             │
// │ FEC: Kayıp %1.2 → Kurtarma %100                  │
// │ Phantom: YouTube profili  Oran: %23               │
// │ Governor: Normal  Kısıtlama riski: DÜŞÜK          │
// │ Çalışma süresi: 3g 14s 22dk                       │
// └───────────────────────────────────────────────────┘
```
**Araç:** golang-pro agent

## Sprint 28–29 — CI/CD DPI Test Hattı (2 hafta)

### Oturum 28.1–28.3 — DPI Test Infrastructure
```yaml
# .github/workflows/dpi-test.yml
# Her commit'te:
# 1. Docker Compose: nabu-client + nabu-relay + nDPI + Suricata
# 2. Headless Chrome: 10 dk tünel trafiği
# 3. nDPI analiz: "HTTPS"/"QUIC" = pass, "Unknown" = warn
# 4. Suricata: sıfır uyarı = pass
# 5. JA3/JA4 fingerprint kontrolü
# 6. Herhangi başarısız = build fail
```
**Araç:** devops-engineer agent

### Oturum 29.1–29.2 — Üretim Sağlamlaştırma
```go
// - Üstel geri çekilme ile yeniden bağlanma
// - Sağlık kontrolü + watchdog goroutine
// - Viper WatchConfig() sıcak reload
// - Çökme-güvenli state (badger veya bbolt)
// - IP yasaklama (5 başarısız auth → ban)
// - Sertifika sabitleme
```

## Sprint 30–32 — Üretim Doğrulama (3 hafta)

### Oturum 30.1–30.3 — Türkiye ISS Testi
```
Test ortamı:
- Türk Telekom SIM (mobil hotspot üzerinden)
- Turkcell SIM
- Vodafone TR SIM  
- TurkNet (DSL/fiber — arkadaş yardımı)

Her ISS için:
1. tünel kur
2. Engelli 50+ siteye eriş (Twitter, YouTube, Wikipedia vb.)
3. throughput ölç
4. DNS sızıntı testleri
5. Bağlantı stabilitesi: 30 dk+
```

### Oturum 31.1–31.2 — Faz 4 Performans Hedefleri
```
✓ > 30 gün sürekli çalışma
✓ Bellek < 100MB (normal yük)
✓ Relay arızasından kurtarma < 2s
✓ 4 büyük Türk ISS'de doğrulandı
```

---

# FAZ 5 — Opsiyonel SaaS (Ay 13+)

## Sprint 33+ — SaaS Mimarisi

### Öncelik 1: Android İstemci
```
- gomobile ile Go → Android AAR
- Basit Kotlin UI (WireGuard uygulaması referans)
- VPN Service API (Android)
- Play Store: NABU — Özgür İnternet
```

### Öncelik 2: Kullanıcı Yönetimi
```go
// PSK → OAuth2/JWT
// Kullanıcı başına trafik izolasyonu
// Faturalandırma: Stripe (Türkiye dışı entity)
```

### Öncelik 3: Otomatik Ölçeklendirme
```
- Terraform Cloud + OCI autoscaling
- Coğrafi yük dengeleme
- Otomatik IP rotasyonu (engelleme tespitinde)
```

---

## 🧪 TEST STRATEJİSİ — TAM LİSTE

### Her Modül İçin (Birim Test)
```
✓ Happy path
✓ Hata durumları (her error return)
✓ Sınır değerleri (0 byte, max MTU, vb.)
✓ Race condition (go test -race)
✓ Memory leak (goleak)
✓ Benchmark (BenchmarkXxx)
Coverage hedefi: > %80 (kripto/network: > %90)
```

### Entegrasyon Testleri
```
✓ Crypto → FEC → Transport zinciri
✓ SOCKS5 → Tünel → Relay
✓ Multipath yük dengeleme
✓ Governor adaptasyon döngüsü
✓ DNS sızıntı önleme
```

### DPI Direnç Testleri (Otomatik CI)
```
✓ nDPI sınıflandırma: HTTPS/QUIC
✓ Suricata: sıfır uyarı
✓ JA3/JA4 tutarlılığı
✓ İlk paket entropi < 7.2
✓ İstatistiksel: KS-testi p > 0.05
```

### E2E Testler
```
✓ Gerçek HTTP istekleri SOCKS5 üzerinden
✓ Throughput: > 50 Mbps (Faz 1), > 40 Mbps (Faz 2+)
✓ Gecikme: < 150ms (3 relay, Avrupa)
✓ Kurtarma: yol arızası < 500ms
✓ DNS sızıntı: sıfır
✓ 30 gün uptime (Faz 4)
```

### Güvenlik Testleri
```
✓ Nonce tekrarı olmadığı
✓ Timing saldırıları (şifreleme sabit zamanlı mı?)
✓ Bellek sıfırlama (PSK sonrası)
✓ TLS parmak izi tutarlılığı
✓ IP yasaklama çalışıyor mu?
✓ Probe tespit
```

---

## 📦 GITHUB REPO YAPISII

```
Organization: nabu-tunnel
Repos:
├── nabu              # Ana Go + Rust monorepo
├── nabu-deploy       # Terraform + Docker Compose
├── nabu-profiles     # Phantom trafik profilleri (PCAP analizi)
└── nabu-research     # Akademik notlar, DPI analizi
```

### Branch Stratejisi
```
main          — kararlı, CI geçmiş
develop       — aktif geliştirme
feat/faz-1    — özellik dalları
```

### Release Süreci
```
git tag v0.1.0 → GitHub Actions → 
  linux/amd64 binary
  linux/arm64 binary  
  Docker image (ghcr.io/nabu-tunnel/nabu)
  SHA256 checksums
```

---

## ⚡ CONTEXT YÖNETİMİ KURALLARI

### Sohbet Başlangıcı (Her Zaman)
```
"NABU projesine devam ediyoruz. 
SESSION_STATE.md dosyasını oku ve devam et."
```

### Context Uyarı Seviyeleri
| Durum | Eylem |
|-------|-------|
| Yeni sohbet | SESSION_STATE.md oku |
| 3 saat geçti | ⚠️ Ben seni uyaracağım — mevcut modülü bitir |
| Uzun tartışma | Kodu yaz, analizi kısa tut |
| Büyük dosya okuma | Sadece ilgili bölümü oku |
| Çok modül aynı anda | Bir modül bitir, sonra diğerine geç |

### Verimli Kodlama İpuçları
```
- Bir oturumda 1 sprint hedefi
- Önce testler (tdd-guide), sonra implementasyon
- Her modül bağımsız commit
- SESSION_STATE her oturum sonu güncellenir
```

---

## 🛠️ ARAÇ KURULUM LİSTESI (OCI VM'de)

```bash
# Go 1.22+
wget https://go.dev/dl/go1.22.3.linux-arm64.tar.gz

# Rust 1.77+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Wire (dependency injection — Faz 3+)
go install github.com/google/wire/cmd/wire@latest

# goreleaser (release binary'leri)
go install github.com/goreleaser/goreleaser@latest

# nDPI (DPI test)
apt install libndpi-dev ndpiReader

# Suricata (IDS test)
apt install suricata

# tshark (pcap analiz)
apt install tshark

# eBPF araçları (Faz 3)
apt install libbpf-dev bpftool clang llvm

# bpf2go (Go eBPF code gen)
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

---

## 📊 BAŞARI METRİKLERİ — GENEL TABLO

| Metrik | Faz 1 | Faz 2 | Faz 3 | Faz 4 |
|--------|-------|-------|-------|-------|
| Throughput | >50 Mbps | >40 Mbps | >40 Mbps | >40 Mbps |
| Tünel kurulum | <500ms | <500ms | <500ms | <500ms |
| nDPI sınıf | Unknown | HTTPS/QUIC | HTTPS/QUIC | HTTPS/QUIC |
| DPI uyarısı | - | 0/24h | 0/24h | 0/24h |
| DNS sızıntı | - | - | 0 | 0 |
| Yol arıza kurtarma | - | - | <500ms | <2s |
| Uptime | - | - | - | >30 gün |
| Test coverage | >80% | >80% | >80% | >85% |

---

## � DEPLOYMENT — Docker Compose (Sunucu + İstemci)

### Ön Gereksinim

```bash
# PSK oluştur (hem relay hem client'ta aynı değer olmalı)
openssl rand -hex 32
```

### Relay Sunucusu (OCI ARM64)

```bash
cd /home/ubuntu/nabu/deploy/docker

# .env oluştur
cp .env.example .env
nano .env          # NABU_PSK'yı doldur

# Sadece relay ayağa kaldır
docker compose up -d nabu-relay

# Log takip
docker compose logs -f nabu-relay
```

Güvenlik Duvarı:

```bash
# OCI Security List veya iptables — UDP portu aç
sudo iptables -A INPUT -p udp --dport 7000 -j ACCEPT
```

### İstemci (dizüstü / yerel cihaz)

```bash
cd /path/to/nabu/deploy/docker

# .env oluştur
cp .env.example .env
# NABU_PSK = relay ile aynı değer
# NABU_RELAY_ADDR = relay'in dış IP'si:7000
nano .env

docker compose up -d nabu-client

# SOCKS5 proxy → localhost:1080
curl --proxy socks5h://127.0.0.1:1080 https://ifconfig.me
```

---

## ⚙️ DEPLOYMENT — Systemd (OCI ARM64 doğrudan kurulum)

### Binary Kurulum

```bash
# Relay sunucusunda
cd /home/ubuntu/nabu
go build -trimpath -ldflags="-s -w" -o /usr/local/bin/nabu-relay ./cmd/nabu-relay
go build -trimpath -ldflags="-s -w" -o /usr/local/bin/nabu-client ./cmd/nabu-client

# Servis kullanıcısı oluştur
sudo useradd -r -s /sbin/nologin nabu
sudo mkdir -p /var/log/nabu && sudo chown nabu:nabu /var/log/nabu
```

### Relay Servis Kurulum

```bash
sudo mkdir -p /etc/nabu

# Env dosyasını kopyala ve düzenle
sudo cp deploy/systemd/relay.env.example /etc/nabu/relay.env
sudo chmod 600 /etc/nabu/relay.env && sudo chown nabu:nabu /etc/nabu/relay.env
sudo nano /etc/nabu/relay.env    # NABU_PSK doldur

# Systemd unit
sudo cp deploy/systemd/nabu-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nabu-relay

# Durum kontrol
sudo systemctl status nabu-relay
sudo journalctl -u nabu-relay -f
```

### İstemci Servis Kurulum

```bash
sudo cp deploy/systemd/client.env.example /etc/nabu/client.env
sudo chmod 600 /etc/nabu/client.env && sudo chown nabu:nabu /etc/nabu/client.env
sudo nano /etc/nabu/client.env    # NABU_PSK ve NABU_RELAY_ADDR doldur

sudo cp deploy/systemd/nabu-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nabu-client

sudo systemctl status nabu-client
sudo journalctl -u nabu-client -f
```

### Hızlı Doğrulama

```bash
# SOCKS5 aracılığıyla dış IP kontrol
curl --proxy socks5h://127.0.0.1:1080 https://ifconfig.me

# Gecikme ölçümü (relay RTT loglarında görünür)
curl -w "connect:%{time_connect}s total:%{time_total}s\n" \
     --proxy socks5h://127.0.0.1:1080 https://1.1.1.1
```

---

## �🚀 BUGÜN BAŞLAMA

Şu an Faz 1, Sprint 1, Oturum 1.1:

```bash
cd /home/ubuntu
mkdir nabu && cd nabu
git init
# GitHub'da nabu-tunnel organization oluştur
# ilk commit
```

**Söyle:** "Oturum 1.1'e başlayalım" → GitHub + Go modül kurulumunu yapıyoruz.
