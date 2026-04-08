package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateX25519KeyPair(t *testing.T) {
	kp1, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	kp2, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("keygen2 failed: %v", err)
	}
	// Two independently generated key pairs must be different.
	if bytes.Equal(kp1.Public[:], kp2.Public[:]) {
		t.Fatal("two distinct key pairs produced same public key")
	}
}

func TestX25519SharedSecretSymmetry(t *testing.T) {
	// Simulate client and relay exchanging public keys.
	client, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("client keygen: %v", err)
	}
	relay, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}

	// Client computes shared secret using relay's public key.
	sharedClient, err := X25519SharedSecret(client.Private[:], relay.Public[:])
	if err != nil {
		t.Fatalf("client shared secret: %v", err)
	}

	// Relay computes shared secret using client's public key.
	sharedRelay, err := X25519SharedSecret(relay.Private[:], client.Public[:])
	if err != nil {
		t.Fatalf("relay shared secret: %v", err)
	}

	if !bytes.Equal(sharedClient, sharedRelay) {
		t.Fatal("X25519 shared secrets do not match (DH symmetry broken)")
	}
}

func TestDeriveSessionKeyX25519Deterministic(t *testing.T) {
	psk := []byte("test-psk")
	client, _ := GenerateX25519KeyPair()
	relay, _ := GenerateX25519KeyPair()

	shared, err := X25519SharedSecret(client.Private[:], relay.Public[:])
	if err != nil {
		t.Fatalf("shared secret: %v", err)
	}

	key1, err := DeriveSessionKeyX25519(psk, shared, client.Public[:], relay.Public[:])
	if err != nil {
		t.Fatalf("derive key 1: %v", err)
	}
	key2, err := DeriveSessionKeyX25519(psk, shared, client.Public[:], relay.Public[:])
	if err != nil {
		t.Fatalf("derive key 2: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("key derivation is not deterministic")
	}
	if len(key1) != AES256KeySize {
		t.Fatalf("expected key length %d, got %d", AES256KeySize, len(key1))
	}
}

func TestDeriveSessionKeyX25519BothSidesAgree(t *testing.T) {
	psk := []byte("nabu-test-psk")
	client, _ := GenerateX25519KeyPair()
	relay, _ := GenerateX25519KeyPair()

	sharedByClient, _ := X25519SharedSecret(client.Private[:], relay.Public[:])
	sharedByRelay, _ := X25519SharedSecret(relay.Private[:], client.Public[:])

	clientKey, err := DeriveSessionKeyX25519(psk, sharedByClient, client.Public[:], relay.Public[:])
	if err != nil {
		t.Fatalf("client derive: %v", err)
	}
	relayKey, err := DeriveSessionKeyX25519(psk, sharedByRelay, client.Public[:], relay.Public[:])
	if err != nil {
		t.Fatalf("relay derive: %v", err)
	}
	if !bytes.Equal(clientKey, relayKey) {
		t.Fatal("client and relay derived different session keys")
	}
}

func TestDeriveSessionKeyX25519ForwardSecrecy(t *testing.T) {
	// Two sessions with the same PSK but different ephemeral keys must yield
	// different session keys — this is the core of forward secrecy.
	psk := []byte("shared-psk")

	makeKey := func() []byte {
		c, _ := GenerateX25519KeyPair()
		r, _ := GenerateX25519KeyPair()
		shared, _ := X25519SharedSecret(c.Private[:], r.Public[:])
		key, _ := DeriveSessionKeyX25519(psk, shared, c.Public[:], r.Public[:])
		return key
	}

	key1 := makeKey()
	key2 := makeKey()

	if bytes.Equal(key1, key2) {
		t.Fatal("two sessions with same PSK produced identical session keys (forward secrecy violation)")
	}
}
