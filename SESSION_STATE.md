# NABU — SESSION STATE
# Bu dosyayı her oturum başında oku, her oturum sonunda güncelle.

## Son Güncelleme
Tarih: 2026-04-07
Oturum: 0 (Başlangıç)

## Mevcut Faz / Sprint / Oturum
- Faz: 1 — Temel UDP Tünel
- Sprint: 1 — Proje Bootstrap
- Oturum: 1.1 — GitHub + Go Modül Kurulumu

## Bir Sonraki Oturum İlk Görevi
```
1. /home/ubuntu/nabu/RUNBOOK.md oku (Oturum 1.1 bölümü)
2. GitHub'da nabu-tunnel organization oluştur (veya personal repo)
3. go mod init github.com/nabu-tunnel/nabu
4. Temel klasör yapısını oluştur (zaten var: /home/ubuntu/nabu/)
5. .github/workflows/ci.yml yaz
6. Makefile hedeflerini yaz
7. AGPL-3.0 LICENSE ekle
```

## Tamamlananlar
- [x] RUNBOOK.md oluşturuldu
- [x] Proje dizin yapısı oluşturuldu (/home/ubuntu/nabu/)
- [x] SESSION_STATE.md oluşturuldu
- [x] Proje hafızaya kaydedildi (/memories/repo/nabu-project.md)

## Yarım Kalanlar
- Yok (henüz kod yazılmadı)

## Açık Sorular / Blokerlar
- GitHub kullanıcı adı / organization adı nedir? (nabu-tunnel önerildi)
- OCI için hangi bölgeler tercih edilmeli? (Marsilya ve Stokholm önerildi)
- Go 1.22+ kurulu mu? → kontrol et: go version

## Notlar
- RUNBOOK.md tüm 5 fazı, tüm sprint ve oturumları içeriyor
- Her oturum 4-5 saat max — 3 saatte uyarı ver
- tdd-guide agent: her yeni modülde önce test yaz
- security-reviewer: kripto ve network kodu için ZORUNLU

## Bağımlılık Durumu
- Go: kurulu mu? → kontrol edilmedi
- Rust: kurulu mu? → Faz 4'te gerekli, şimdilik opsiyonel
- nDPI: → Faz 1 sonu DPI testleri için gerekli
- Docker: kurulu (zaten kullanılıyor)
