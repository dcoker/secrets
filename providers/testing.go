package providers

import (
	"bytes"
)

const (
	testingLabel = "testing"
)

func init() {
	registry[testingLabel] = NewTestingProvider
}

// testingKeys is a key provider that uses a constant key. testingKeys is only to be used for
// integration testing.
type testingKeys struct{}

var (
	testingPlaintext  = bytes.Repeat([]byte{'x'}, 32)
	testingCiphertext = bytes.Repeat([]byte{'y'}, 32)
)

// NewTestingProvider returns a new testingKeys.
func NewTestingProvider() Provider {
	return &testingKeys{}
}

// GenerateEnvelopeKey generates an EnvelopeKey under a specific KeyID.
func (k *testingKeys) GenerateEnvelopeKey(keyID string) (EnvelopeKey, error) {
	return EnvelopeKey{
		testingPlaintext,
		testingCiphertext,
	}, nil
}

// Decrypt decrypts the encrypted key.
func (k *testingKeys) Decrypt(keyCiphertext []byte) ([]byte, error) {
	return testingPlaintext, nil
}

// Label returns testingLabel
func (k *testingKeys) Label() string {
	return testingLabel
}
