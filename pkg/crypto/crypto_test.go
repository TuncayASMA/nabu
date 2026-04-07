package crypto

import (
	"bytes"
	"sync"
	"testing"
)

func mustKey() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := mustKey()
	plain := []byte("nabu test payload")

	ciphertext, err := Encrypt(plain, key)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if !bytes.Equal(plain, decrypted) {
		t.Fatalf("roundtrip mismatch got=%q want=%q", string(decrypted), string(plain))
	}
}

func TestEncryptRejectsInvalidInput(t *testing.T) {
	if _, err := Encrypt([]byte{}, mustKey()); err == nil {
		t.Fatal("expected error for empty plaintext")
	}
	if _, err := Encrypt([]byte("ok"), []byte("short")); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestDecryptTamperingFails(t *testing.T) {
	key := mustKey()
	plain := []byte("tamper me")

	ciphertext, err := Encrypt(plain, key)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	ciphertext[len(ciphertext)-1] ^= 0x01
	if _, err := Decrypt(ciphertext, key); err == nil {
		t.Fatal("expected decrypt error for tampered ciphertext")
	}
}

func TestEncryptSameInputDifferentCiphertext(t *testing.T) {
	key := mustKey()
	plain := []byte("same payload")

	c1, err := Encrypt(plain, key)
	if err != nil {
		t.Fatalf("encrypt1 failed: %v", err)
	}
	c2, err := Encrypt(plain, key)
	if err != nil {
		t.Fatalf("encrypt2 failed: %v", err)
	}

	if bytes.Equal(c1, c2) {
		t.Fatal("expected different ciphertext due to random nonce")
	}
}

func TestDeriveSessionKey(t *testing.T) {
	master := []byte("master-secret-key-material")
	salt := []byte("relay-unique-salt")

	k1, err := DeriveSessionKey(master, salt, 32)
	if err != nil {
		t.Fatalf("derive1 failed: %v", err)
	}
	k2, err := DeriveSessionKey(master, salt, 32)
	if err != nil {
		t.Fatalf("derive2 failed: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("expected deterministic keys for same input")
	}

	k3, err := DeriveSessionKey(master, []byte("different-salt"), 32)
	if err != nil {
		t.Fatalf("derive3 failed: %v", err)
	}
	if bytes.Equal(k1, k3) {
		t.Fatal("expected different keys for different salt")
	}
}

func TestNonceGeneratorUniqueness(t *testing.T) {
	ng := NewNonceGenerator()
	seen := make(map[[GCMNonceSize]byte]struct{})

	for range 500 {
		n, err := ng.Generate()
		if err != nil {
			t.Fatalf("nonce generation failed: %v", err)
		}
		if _, ok := seen[n]; ok {
			t.Fatal("duplicate nonce detected")
		}
		seen[n] = struct{}{}
	}
}

func TestNonceGeneratorConcurrent(t *testing.T) {
	ng := NewNonceGenerator()
	var wg sync.WaitGroup
	out := make(chan [GCMNonceSize]byte, 256)
	errCh := make(chan error, 1)

	for range 256 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := ng.Generate()
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			out <- n
		}()
	}

	wg.Wait()
	close(out)
	close(errCh)

	if err := <-errCh; err != nil {
		t.Fatalf("concurrent nonce error: %v", err)
	}

	seen := make(map[[GCMNonceSize]byte]struct{})
	for n := range out {
		if _, ok := seen[n]; ok {
			t.Fatal("duplicate nonce in concurrent generation")
		}
		seen[n] = struct{}{}
	}
}

func BenchmarkEncrypt1KB(b *testing.B) {
	key := mustKey()
	plain := bytes.Repeat([]byte("a"), 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Encrypt(plain, key); err != nil {
			b.Fatalf("encrypt failed: %v", err)
		}
	}
}
