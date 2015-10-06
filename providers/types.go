package providers

import "sort"

var (
	registry = make(map[string]func() Provider)
)

// New returns an Algorithm corresponding to the requested cipher.
func New(label string) Provider {
	if constructor, present := registry[label]; present {
		return constructor()
	}
	return nil
}

// GetDefaultProvider returns the default key provider label.
func GetDefaultProvider() string {
	return kmsLabel
}

// GetProviders returns a list of registered key providers.
func GetProviders() []string {
	var collector []string
	for k := range registry {
		collector = append(collector, k)
	}
	sort.Strings(collector)
	return collector
}

// Provider represents a service that can generate envelope keys and decrypt data encrypted with
// those keys.
type Provider interface {
	GenerateEnvelopeKey(keyID string) (EnvelopeKey, error)
	Decrypt(keyMetadata []byte) ([]byte, error)
	Label() string
}

// EnvelopeKey represents the key used in envelope encryption.
type EnvelopeKey struct {
	// Plaintext is the plaintext encryption key.
	Plaintext []byte
	// Ciphertext is the ciphertext of the encryption key, encrypted with a key that is managed
	// by the provider.
	Ciphertext []byte
}

// GetPlaintext32 returns the Plaintext key as a byte array.
func (e *EnvelopeKey) GetPlaintext32() *[32]byte {
	var plaintextArray [32]byte
	copy(plaintextArray[:], e.Plaintext)
	return &plaintextArray
}
