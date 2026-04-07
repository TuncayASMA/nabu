package crypto

import (
	"crypto/rand"
	"fmt"
)

type NonceGenerator struct{}

func NewNonceGenerator() *NonceGenerator {
	return &NonceGenerator{}
}

func (ng *NonceGenerator) Generate() ([GCMNonceSize]byte, error) {
	var nonce [GCMNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return [GCMNonceSize]byte{}, fmt.Errorf("nonce generation failed: %w", err)
	}
	return nonce, nil
}
