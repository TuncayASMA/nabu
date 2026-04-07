# NABU — UDP Tabanlı Anti-DPI Tünel

[![CI](https://github.com/nabu-tunnel/nabu/actions/workflows/ci.yml/badge.svg)](https://github.com/nabu-tunnel/nabu/actions)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

> **⚠️ Geliştirme aşamasında — henüz production kullanımı için hazır değil.**

NABU, derin paket inceleme (DPI) sistemlerini atlayan, UDP/QUIC tabanlı, açık kaynaklı bir tünel protokolüdür.  
Türkiye, Pakistan, Mısır ve benzer Sandvine altyapısı kullanan ülkelerdeki internet sansürünü aşmak için tasarlanmıştır.

## Özellikler (Yol Haritası)

- 🔐 AES-256-GCM şifreleme (ARM64 donanım hızlandırmalı)
- 🌊 Micro-Phantom trafik gizleme (gerçek HTTPS'ten ayırt edilemez)
- 📦 Reed-Solomon FEC (paket kayıplarında veri kurtarma)
- 🧅 SOCKS5 proxy arayüzü
- 🛡️ DNS sızıntı önleme (DoH/3)
- 🔍 Governor — gerçek zamanlı DPI tespiti

## Hızlı Başlangıç

```bash
# Henüz hazır değil — geliştirme devam ediyor
go install github.com/nabu-tunnel/nabu/cmd/nabu-client@latest
```

## Derleme

```bash
git clone https://github.com/nabu-tunnel/nabu
cd nabu
make build

# Tüm platformlar için
make build-all
```

## Testler

```bash
make test
make test-race
```

## Katkı

AGPL-3.0 lisansı altında açık kaynak. Katkılar için [CONTRIBUTING.md](docs/CONTRIBUTING.md) belgesi yakında eklenecek.

## Lisans

[GNU Affero General Public License v3.0](LICENSE)
