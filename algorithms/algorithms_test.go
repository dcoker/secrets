package algorithms

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlgorithms(t *testing.T) {
	var testInputs = []string{"", " ", "a", "ab", "12345678", "123456789",
		strings.Repeat("beef", 128)}

	var key, wrongKey [32]byte
	rand.Read(key[:])
	rand.Read(wrongKey[:])

	for _, label := range GetAlgorithms() {
		if label == plaintextLabel {
			continue
		}
		algo, err := New(label)
		assert.NoError(t, err)
		for _, expected := range testInputs {
			ciphertext, err := algo.Encrypt(&key, []byte(expected))
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			// attempt to decrypt with wrong key
			if _, err = algo.Decrypt(&wrongKey, ciphertext); err == nil {
				t.Errorf("expected error but didn't get one")
			}
			// decrypt with correct key
			plaintext, err := algo.Decrypt(&key, ciphertext)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if bytes.Compare([]byte(expected), plaintext) != 0 {
				t.Errorf("expected: [%d]%v  plaintext: [%d]%v", len(expected), expected, len(plaintext),
					plaintext)
			}
			// mutate a few bytes and verify that it fails to decrypt
			rand.Read(ciphertext[0:4])
			_, err = algo.Decrypt(&key, ciphertext)
			assert.Error(t, err)
		}
	}
}
