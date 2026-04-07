# NABU — SESSION STATE
# Bu dosyayı her oturum başında oku, her oturum sonunda güncelle.

## Son Güncelleme
Tarih: 2026-04-07
Oturum: 1.1 (Tamamlandı)

## Mevcut Faz / Sprint / Oturum
- Faz: 1 — Temel UDP Tünel
- Sprint: 1 — Proje Bootstrap
- Oturum: 1.2 — pkg/crypto AES-256-GCM + ilk testler

## Bir Sonraki Oturum İlk Görevi
```
1. pkg/crypto/cipher.go → AES-256-GCM şifreleyici (önce test yaz!)
2. pkg/crypto/cipher_test.go → TestEncryptDecrypt, TestTampering, BenchmarkEncrypt
3. pkg/crypto/session.go → oturum anahtarı türetme (HKDF-SHA256)
4. go mod tidy — golang.org/x/crypto eklenecek
5. make test-race → başarılı olmalı
6. GitHub'da nabu-tunnel org veya personal repo oluştur ve push et
```

## Tamamlananlar
- [x] RUNBOOK.md oluşturuldu
- [x] Proje dizin yapısı oluşturuldu (/home/ubuntu/nabu/)
- [x] SESSION_STATE.md oluşturuldu
- [x] Proje hafızaya kaydedildi (/memories/repo/nabu-project.md)
- [x] Go 1.26.1 linux/arm64 kuruldu (/usr/local/go)
- [x] go mod init github.com/nabu-tunnel/nabu
- [x] Makefile (build/test/lint/cross-compile)
- [x] AGPL-3.0 LICENSE
- [x] .github/workflows/ci.yml (test + lint + 4 platform matrix)
- [x] cmd/nabu-client/main.go + cmd/nabu-relay/main.go
- [x] pkg/version/version.go (ldflags inject)
- [x] İlk git commit: ead609e

## Yarım Kalanlar
- Yok (henüz kod yazılmadı)

## Açık Sorular / Blokerlar
- GitHub kullanıcı adı / organization adı nedir? → "nabu-tunnel" önerildi, kullanıcı onayı bekleniyor
- OCI için hangi bölgeler tercih edilmeli? (Marsilya ve Stokholm önerildi)
- GitHub push yapılmadı → remote henüz yok (önce repo oluştur)

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
- GitHub remote: ❌ henüz push edilmedi
