package crypto

import (
	"errors"
	"fmt"
	"io"

	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
)

var (
	ErrEmptyMasterKey    = errors.New("master key cannot be empty")
	ErrEmptySalt         = errors.New("salt cannot be empty")
	ErrInvalidKeyOutSize = errors.New("key length must be between 1 and 64")
)

func DeriveSessionKey(masterKey, salt []byte, keyLength int) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, ErrEmptyMasterKey
	}
	if len(salt) == 0 {
		return nil, ErrEmptySalt
	}
	if keyLength <= 0 || keyLength > 64 {
		return nil, ErrInvalidKeyOutSize
	}

	r := hkdf.New(sha256.New, masterKey, salt, []byte("nabu-session-key"))
	out := make([]byte, keyLength)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf derivation failed: %w", err)
	}
	return out, nil
}
