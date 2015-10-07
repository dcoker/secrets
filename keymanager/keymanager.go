package keymanager

import (
	"errors"
	"sort"
)

var (
	registry                 = make(map[string]func() KeyManager)
	errUnsupportedKeyManager = errors.New("keymanager: unsupported key manager")
)

// New returns a KeyManager of the requested type.
func New(label string) (KeyManager, error) {
	if constructor, present := registry[label]; present {
		return constructor(), nil
	}
	return nil, errUnsupportedKeyManager
}

// GetDefaultKeyManager returns the default key managerlabel.
func GetDefaultKeyManager() string {
	return kmsLabel
}

// GetKeyManagers returns a list of registered key managers.
func GetKeyManagers() []string {
	var collector []string
	for k := range registry {
		collector = append(collector, k)
	}
	sort.Strings(collector)
	return collector
}

// KeyManager represents a service that can generate envelope keys and provide decryption
// keys.
type KeyManager interface {
	GenerateEnvelopeKey(keyID string) (EnvelopeKey, error)
	Decrypt(keyMetadata []byte) ([]byte, error)
	Label() string
}

// EnvelopeKey represents the key used in envelope encryption.
type EnvelopeKey struct {
	// Plaintext is the plaintext encryption key.
	Plaintext []byte
	// Ciphertext is the ciphertext of the encryption key, encrypted with a key that is managed
	// by the key manager..
	Ciphertext []byte
}

// GetPlaintext32 returns the Plaintext key as a byte array.
func (e *EnvelopeKey) GetPlaintext32() *[32]byte {
	var plaintextArray [32]byte
	copy(plaintextArray[:], e.Plaintext)
	return &plaintextArray
}
