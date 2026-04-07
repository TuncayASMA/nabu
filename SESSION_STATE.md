# NABU — SESSION STATE
# Bu dosyayı her oturum başında oku, her oturum sonunda güncelle.

## Son Güncelleme
Tarih: 2026-04-07
Oturum: 1.3 (Tamamlandı)

## Mevcut Faz / Sprint / Oturum
- Faz: 1 — Temel UDP Tünel
- Sprint: 1 — Proje Bootstrap
- Oturum: 1.4 — pkg/socks5 server skeleton + testler

## Bir Sonraki Oturum İlk Görevi
```
1. pkg/socks5/server.go -> listener, auth-less SOCKS5 handshake skeleton
2. pkg/socks5/server_test.go -> handshake parse testleri
3. cmd/nabu-client entegrasyonu için local socks config bağlama
4. make test-race ve go test ./... temiz
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

## Yarım Kalanlar
- Yok (henüz kod yazılmadı)

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

## Bağımlılık Durumu
 - Go: ✅ go1.26.1 linux/arm64 — /usr/local/go/bin/go
- Rust: ❌ Faz 4'te gerekli, şimdilik opsiyonel
- nDPI: ❌ Faz 1 sonu DPI testleri için gerekli
- Docker: ✅ Docker 29.1.5 kurulu
- GitHub remote: ✅ origin -> https://github.com/TuncayASMA/nabu.git
