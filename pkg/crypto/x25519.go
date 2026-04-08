package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const (
	// X25519PublicKeySize is the size of an X25519 public key in bytes.
	X25519PublicKeySize = 32
	// X25519PrivateKeySize is the size of an X25519 private key (scalar) in bytes.
	X25519PrivateKeySize = 32
)

var ErrInvalidX25519Key = errors.New("invalid X25519 key size")

// X25519KeyPair holds an ephemeral X25519 key pair.
type X25519KeyPair struct {
	Private [X25519PrivateKeySize]byte
	Public  [X25519PublicKeySize]byte
}

// GenerateX25519KeyPair generates a fresh ephemeral X25519 key pair.
func GenerateX25519KeyPair() (X25519KeyPair, error) {
	var kp X25519KeyPair
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return X25519KeyPair{}, fmt.Errorf("private key generation failed: %w", err)
	}
	// Clamp per RFC 7748 §5.
	kp.Private[0] &= 248
	kp.Private[31] &= 127
	kp.Private[31] |= 64

	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return X25519KeyPair{}, fmt.Errorf("public key derivation failed: %w", err)
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// X25519SharedSecret computes the Diffie-Hellman shared secret from a local
// private key and a peer's public key.
func X25519SharedSecret(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != X25519PrivateKeySize {
		return nil, fmt.Errorf("%w: private key", ErrInvalidX25519Key)
	}
	if len(peerPublicKey) != X25519PublicKeySize {
		return nil, fmt.Errorf("%w: peer public key", ErrInvalidX25519Key)
	}
	shared, err := curve25519.X25519(privateKey, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("X25519 DH failed: %w", err)
	}
	return shared, nil
}

// DeriveSessionKeyX25519 derives a 32-byte AES-256 session key using:
//
//	HKDF-SHA256(ikm = PSK || sharedSecret, salt = clientPub || relayPub, info = "nabu-session-key")
//
// This ties the session key to both the pre-shared secret (authentication) and
// the ephemeral DH exchange (forward secrecy).
func DeriveSessionKeyX25519(psk, sharedSecret, clientPub, relayPub []byte) ([]byte, error) {
	// IKM = PSK concatenated with DH shared secret.
	ikm := make([]byte, len(psk)+len(sharedSecret))
	copy(ikm, psk)
	copy(ikm[len(psk):], sharedSecret)

	// Salt = client public key || relay public key (session-unique).
	salt := make([]byte, len(clientPub)+len(relayPub))
	copy(salt, clientPub)
	copy(salt[len(clientPub):], relayPub)

	return DeriveSessionKey(ikm, salt, AES256KeySize)
}
