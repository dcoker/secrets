package keymanager

import (
	"bytes"
)

const (
	testingLabel = "testing"
)

func init() {
	registry[testingLabel] = newTestingKeyManager
}

// testingKeys is a key manager that uses a constant key. testingKeys is only to be used for
// integration testing.
type testingKeys struct{}

var (
	testingPlaintext  = bytes.Repeat([]byte{'x'}, 32)
	testingCiphertext = bytes.Repeat([]byte{'y'}, 32)
)

// NewTestingKeyManager returns a new testingKeys.
func newTestingKeyManager() KeyManager {
	return &testingKeys{}
}

// GenerateEnvelopeKey generates an EnvelopeKey under a specific KeyID.
func (k *testingKeys) GenerateEnvelopeKey(keyID, secretID string) (EnvelopeKey, error) {
	return EnvelopeKey{
		testingPlaintext,
		testingCiphertext,
	}, nil
}

// Decrypt decrypts the encrypted key.
func (k *testingKeys) Decrypt(keyCiphertext []byte, secretID string) ([]byte, error) {
	return testingPlaintext, nil
}

// Label returns testingLabel
func (k *testingKeys) Label() string {
	return testingLabel
}
