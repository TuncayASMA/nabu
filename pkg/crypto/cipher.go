package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

const (
	AES256KeySize = 32
	GCMNonceSize  = 12
)

var (
	ErrEmptyPlaintext     = errors.New("plaintext cannot be empty")
	ErrInvalidKeyLength   = errors.New("key length must be 32 bytes for AES-256")
	ErrCiphertextTooShort = errors.New("ciphertext too short")
	defaultNonceGenerator = NewNonceGenerator()
)

func Encrypt(plaintext, key []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, ErrEmptyPlaintext
	}
	if len(key) != AES256KeySize {
		return nil, ErrInvalidKeyLength
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes init failed: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init failed: %w", err)
	}

	nonceArray, err := defaultNonceGenerator.Generate()
	if err != nil {
		return nil, err
	}
	nonce := nonceArray[:]

	sealed := aead.Seal(nil, nonce, plaintext, nil)
	result := make([]byte, 0, len(nonce)+len(sealed))
	result = append(result, nonce...)
	result = append(result, sealed...)
	return result, nil
}

func Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, ErrInvalidKeyLength
	}
	if len(ciphertext) <= GCMNonceSize {
		return nil, ErrCiphertextTooShort
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes init failed: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init failed: %w", err)
	}

	nonce := ciphertext[:GCMNonceSize]
	payload := ciphertext[GCMNonceSize:]

	plaintext, err := aead.Open(nil, nonce, payload, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
