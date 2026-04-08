package obfuscation

import (
	nabuCrypto "github.com/TuncayASMA/nabu/pkg/crypto"
)

// encryptPayload encrypts plain with AES-256-GCM using key.
// It delegates to the shared crypto package to keep algorithm logic centralised.
func encryptPayload(plain, key []byte) ([]byte, error) {
	return nabuCrypto.Encrypt(plain, key)
}

// decryptPayload decrypts cipher with AES-256-GCM using key.
func decryptPayload(cipher, key []byte) ([]byte, error) {
	return nabuCrypto.Decrypt(cipher, key)
}
