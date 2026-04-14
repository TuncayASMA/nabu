
# NABU — Modern Anti-DPI UDP Tünel Katmanı

[![CI](https://github.com/TuncayASMA/nabu/actions/workflows/ci.yml/badge.svg)](https://github.com/TuncayASMA/nabu/actions) [![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

<p align="center">
	<img src="docs/assets/nabu-hero.svg" width="320" alt="NABU Hero" />
</p>

> **⚠️ Bu proje aktif geliştirme aşamasındadır. Production ortamında kullanmadan önce test ve inceleme yapınız.**

NABU, DPI (Deep Packet Inspection) ve sansür mekanizmalarını aşmak için UDP/QUIC tabanlı, şifreli ve obfuscation destekli modern bir tünel katmanıdır. Açık kaynak, denetlenebilir ve topluluk odaklıdır.

---

## 🚀 Kısa Özet

NABU; masaüstü ve (yolda olan) mobil istemciler için, yerel SOCKS5 proxy üzerinden trafiği şifreli UDP relay sunucularına taşır. Amaç, gerçek internet davranışına yakın trafik üretip DPI engellerini aşmak ve özgür erişimi mümkün kılmaktır.

---


## Temel Akış (Nasıl Çalışır?)

1. **Uygulama** → yerel **SOCKS5 proxy** (NABU Client)
2. **NABU Client** → şifreli & gizlenmiş UDP/QUIC relay hattı
3. **Relay sunucu** → hedef internete çıkış

Kullanıcı uygulamaları (tarayıcı, Telegram, vs.) SOCKS5 üzerinden NABU'ya bağlanır; trafik, DPI engellerini aşacak şekilde relay'e taşınır.

---


## Hedef Kullanıcılar & Senaryolar

- Ağında DPI/sansür bulunan ülkelerde/kurumlarda çalışan teknik kullanıcılar
- Kendi relay altyapısını kurmak isteyen bireyler/ekipler
- Açık kaynak, denetlenebilir ve topluluk odaklı tünel mimarisi arayanlar
- Mobilde ve masaüstünde özgür internet erişimi isteyenler

---


## Kullanım Şartları & Uyarılar

- Yalnızca yerel mevzuata uygun ve yetkili kullanımda kullanınız.
- Relay altyapısı ve trafik politikası tamamen kullanıcı sorumluluğundadır.
- Her ortamda aynı performans garanti edilmez.
- Aktif geliştirme: Sürüm notları ve CI durumu takip edilmelidir.

---


## Sistem Gereksinimleri

- **İşletim sistemi:** Linux (tam destek), macOS/Windows (istemci binary)
- **Çalıştırma:** Docker Compose veya native Go toolchain
- **Ağ:** Relay'e UDP erişimi (varsayılan 7000/udp), istemci için 1080/tcp
- **Kimlik:** Ortak PSK (ön paylaşımlı anahtar)
- **Opsiyonel:** DNS sızıntı önleme için iptables/ip6tables yetkisi
- **Opsiyonel:** TLS/WSS/QUIC maskeleri için sertifika ve uygun port/policy

---


## Platform Desteği

| Platform      | İstemci | Relay | Durum         |
|-------------- |---------|-------|--------------|
| Linux         | ✔️      | ✔️    | Tam destek    |
| macOS         | ✔️      | —     | Binary (test) |
| Windows       | ✔️      | —     | Binary (test) |
| Android/iOS   | 🚧      | —     | Planlandı     |

> Mobilde tam deneyim için platforma özel ağ entegrasyonu (VPN/TUN) gereklidir.

---


## Yol Haritası & Evrensel Destek

1. **Desktop stabilizasyonu:**
   - Windows/macOS istemci smoke testleri (CI)
   - Platforma özel kurulum paketleri ve dokümantasyon
2. **Mobil çekirdek:**
   - Tünel mantığının mobilde yeniden kullanılabilir API'ye ayrılması
   - Android/iOS için güvenli anahtar yönetimi
3. **Native mobil istemci:**
   - Android (Kotlin) ve iOS (Swift) istemci uygulamaları
   - Network Extension/VPN entegrasyonu
4. **Operasyonel kalite:**
   - Desktop/mobile için E2E test havuzu
   - Pil, ağ geçişi, bağlantı toparlama metrikleri

---


## Proje Amacı

- Sansürlü ağlarda güvenilir ve özgür bağlantı sağlamak
- Trafiği gerçek internet davranışına benzeterek engel riskini düşürmek
- Topluluk tarafından geliştirilebilen, denetlenebilir bir altyapı sunmak

---


## Temel Özellikler

- Yerelde SOCKS5 endpoint sunar (uygulamalar kolayca bağlanır)
- Trafiği relay üzerinden şifreli UDP ile taşır
- DNS sızıntısını önlemek için güvenli DNS taşıma modları
- DPI tepki analizi ve çok yollu taşıma (yolda)

---


## Teknik Özellikler

- 🔐 **AES-256-GCM şifreleme:** ARM64 donanım hızlandırmalı
- 🌊 **Micro-Phantom trafik gizleme:** Gerçek HTTPS'ten ayırt edilemez
- 📦 **Reed-Solomon FEC:** Paket kayıplarında veri kurtarma
- 🧅 **SOCKS5 proxy arayüzü**
- 🛡️ **DNS sızıntı önleme:** DoH/3
- 🔍 **Governor:** Gerçek zamanlı DPI tespiti

---


## Hızlı Başlangıç

```bash
# Geliştirme aşamasında — test ortamında deneyin
git clone https://github.com/TuncayASMA/nabu
cd nabu
make build
# veya
go install github.com/TuncayASMA/nabu/cmd/nabu-client@latest
```

Kurulum ve kullanım detayları için [docs/](docs/) klasörüne bakınız.

---


## Varsayılan Kararlar

- Relay varsayılan UDP portu: `443`
- Demo relay: `OCI Marseille (fr-mrs-1)`
- Konfig modeli: `hybrid` (dosya + CLI override)
- WireGuard uyumluluğu: açık (`--wg-compatible=true`)
- Organizasyon: İlk dış katkı sonrası `nabu-tunnel` org'a taşınacak

---


## Sıkça Sorulanlar (FAQ)

**NABU neden UDP kullanıyor?**

UDP, DPI engellerini aşmak ve gerçek zamanlı trafik benzetimi için TCP'ye göre daha esnektir. QUIC ve UDP tabanlı protokoller, modern DPI sistemlerinde daha zor tespit edilir.

**Relay sunucusu zorunlu mu?**

Evet, kendi relay sunucunuz veya güvendiğiniz bir relay altyapısı gereklidir.

**Mobil istemci ne zaman hazır olacak?**

Yol haritası bölümünde güncel durum paylaşılır. Katkı vermek isteyenler için [CONTRIBUTING.md](docs/CONTRIBUTING.md) yakında eklenecek.

---


## Derleme

```bash
make build        # Yerel platform için
make build-all    # Tüm platformlar için
```

---


## Testler

```bash
make test         # Birim testler
make test-race    # Race condition testi
make dns-e2e      # DNS E2E testi
make rollout-live # Preflight + test + build
```

---


## Katkı

AGPL-3.0 lisansı altında açık kaynak. Katkı ve PR için [CONTRIBUTING.md](docs/CONTRIBUTING.md) (çok yakında).

---


## Lisans

[GNU Affero General Public License v3.0](LICENSE)
