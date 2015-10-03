package providers

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
