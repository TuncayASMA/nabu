package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestSalamanderRoundTrip(t *testing.T) {
	t.Parallel()
	psk := []byte("super-secret-salamander-psk!!!")
	plain := []byte("hello nabu salamander")

	enc, err := SalamanderEncode(psk, plain)
	if err != nil {
		t.Fatalf("SalamanderEncode: %v", err)
	}

	// Encoded output must be longer than plaintext by exactly SalamanderOverhead.
	if want := len(plain) + SalamanderOverhead; len(enc) != want {
		t.Errorf("encoded len = %d, want %d", len(enc), want)
	}

	dec, err := SalamanderDecode(psk, enc)
	if err != nil {
		t.Fatalf("SalamanderDecode: %v", err)
	}
	if !bytes.Equal(dec, plain) {
		t.Errorf("decoded %q, want %q", dec, plain)
	}
}

// Each call must produce a different ciphertext even for the same plaintext
// (demonstrates fresh salt per frame).
func TestSalamanderNonDeterministic(t *testing.T) {
	t.Parallel()
	psk := []byte("test-psk-32-bytes-salamander!!")
	plain := []byte("same-payload")

	enc1, _ := SalamanderEncode(psk, plain)
	enc2, _ := SalamanderEncode(psk, plain)

	if bytes.Equal(enc1, enc2) {
		t.Error("SalamanderEncode produced identical ciphertext for the same plaintext — salt is not random")
	}
}

func TestSalamanderWrongPSK(t *testing.T) {
	t.Parallel()
	psk := []byte("correct-psk-42-bytes-salamander!!")
	enc, err := SalamanderEncode(psk, []byte("secret"))
	if err != nil {
		t.Fatalf("SalamanderEncode: %v", err)
	}

	_, err = SalamanderDecode([]byte("wrong-psk-00000000000000000000"), enc)
	if err == nil {
		t.Error("SalamanderDecode with wrong PSK should have failed")
	}
}

func TestSalamanderShortPacket(t *testing.T) {
	t.Parallel()
	_, err := SalamanderDecode([]byte("psk"), []byte("short"))
	if !errors.Is(err, ErrSalamanderShortPacket) {
		t.Errorf("expected ErrSalamanderShortPacket, got %v", err)
	}
}

func TestSalamanderEmptyPSK(t *testing.T) {
	t.Parallel()
	_, err := SalamanderEncode(nil, []byte("data"))
	if err == nil {
		t.Error("expected error for empty PSK")
	}
	_, err = SalamanderDecode(nil, []byte("data-that-is-long-enough-for-header"))
	if err == nil {
		t.Error("expected error for empty PSK on decode")
	}
}

func TestSalamanderEmptyPayload(t *testing.T) {
	t.Parallel()
	_, err := SalamanderEncode([]byte("psk"), nil)
	if err == nil {
		t.Error("expected error for empty payload")
	}
}

func TestSalamanderTamperedPacket(t *testing.T) {
	t.Parallel()
	psk := []byte("psk-tamper-test-32-bytes-abc!!")
	enc, err := SalamanderEncode(psk, []byte("tamper-me"))
	if err != nil {
		t.Fatalf("SalamanderEncode: %v", err)
	}
	// Flip a bit in the ciphertext area.
	enc[len(enc)-1] ^= 0xFF

	_, err = SalamanderDecode(psk, enc)
	if err == nil {
		t.Error("SalamanderDecode should have failed for tampered packet")
	}
}
