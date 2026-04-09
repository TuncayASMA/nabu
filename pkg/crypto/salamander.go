package crypto

// Salamander UDP obfuscation — per-frame AES-256-GCM with fresh random salt.
//
// Wire format (appended to every UDP datagram):
//
//	┌──────────┬──────────────┬────────────────────────────────┐
//	│  8 bytes │   12 bytes   │  N+16 bytes                    │
//	│  salt    │  GCM nonce   │  AES-256-GCM ciphertext + tag  │
//	└──────────┴──────────────┴────────────────────────────────┘
//
// A fresh salt is generated for every SalamanderEncode call; the 32-byte AES
// frame key is derived as HKDF-SHA256(psk, salt, "nabu-salamander-v1").  To a
// passive observer every datagram looks like uniformly random bytes — there is
// no fixed header, no length prefix, and no IV reuse.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	SalamanderSaltLen = 8
	SalamanderKeyLen  = AES256KeySize // 32

	salamanderNonceLen = 12 // GCM standard nonce
	salamanderTagLen   = 16 // GCM authentication tag

	// SalamanderOverhead is the fixed byte overhead added to every encoded frame.
	SalamanderOverhead = SalamanderSaltLen + salamanderNonceLen + salamanderTagLen

	salamanderInfo = "nabu-salamander-v1"
)

// ErrSalamanderShortPacket is returned by SalamanderDecode when the packet is
// too short to contain the salt + nonce + GCM tag.
var ErrSalamanderShortPacket = errors.New("salamander: packet too short")

// SalamanderEncode wraps payload in a Salamander envelope.  The returned slice
// can be sent as a UDP datagram and decoded with SalamanderDecode on the other
// side, provided both parties share psk.
func SalamanderEncode(psk, payload []byte) ([]byte, error) {
	if len(psk) == 0 {
		return nil, errors.New("salamander: psk must not be empty")
	}
	if len(payload) == 0 {
		return nil, errors.New("salamander: payload must not be empty")
	}

	// Random salt — fresh per frame to prevent key reuse.
	salt := make([]byte, SalamanderSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("salamander: rand salt: %w", err)
	}

	frameKey, err := salamanderDeriveKey(psk, salt)
	if err != nil {
		return nil, err
	}

	gcm, err := salamanderGCM(frameKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, salamanderNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("salamander: rand nonce: %w", err)
	}

	ct := gcm.Seal(nil, nonce, payload, nil)

	out := make([]byte, 0, SalamanderSaltLen+salamanderNonceLen+len(ct))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// SalamanderDecode reverses SalamanderEncode using the shared psk.
// Returns ErrSalamanderShortPacket if packet is too short.
// Returns an error wrapping cipher.ErrAuthFailed if the packet was tampered
// with or the psk does not match.
func SalamanderDecode(psk, packet []byte) ([]byte, error) {
	if len(psk) == 0 {
		return nil, errors.New("salamander: psk must not be empty")
	}
	if len(packet) < SalamanderSaltLen+salamanderNonceLen+salamanderTagLen {
		return nil, ErrSalamanderShortPacket
	}

	salt := packet[:SalamanderSaltLen]
	nonce := packet[SalamanderSaltLen : SalamanderSaltLen+salamanderNonceLen]
	ct := packet[SalamanderSaltLen+salamanderNonceLen:]

	frameKey, err := salamanderDeriveKey(psk, salt)
	if err != nil {
		return nil, err
	}

	gcm, err := salamanderGCM(frameKey)
	if err != nil {
		return nil, err
	}

	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("salamander: decrypt: %w", err)
	}
	return plain, nil
}

// salamanderDeriveKey derives a 32-byte AES key via HKDF-SHA256(psk, salt, info).
func salamanderDeriveKey(psk, salt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, psk, salt, []byte(salamanderInfo))
	key := make([]byte, SalamanderKeyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("salamander: hkdf: %w", err)
	}
	return key, nil
}

func salamanderGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("salamander: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("salamander: gcm: %w", err)
	}
	return gcm, nil
}
