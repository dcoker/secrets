package algorithms

import (
	"crypto/rand"

	"errors"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	secretBoxLabel = "secretbox"
)

func init() {
	registry[secretBoxLabel] = newSecretBox
}

var (
	errUnableToDecrypt = errors.New("secretbox: unable to decrypt")
)

type secretBox struct{}

func newSecretBox() Algorithm {
	return &secretBox{}
}

func (s *secretBox) Encrypt(key *[32]byte, data []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return secretbox.Seal(nonce[:], data, &nonce, key), nil
}

func (s *secretBox) Decrypt(key *[32]byte, ciphertext []byte) ([]byte, error) {
	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])
	var out []byte
	out, ok := secretbox.Open(out[:0], ciphertext[24:], &nonce, key)
	if !ok {
		return nil, errUnableToDecrypt
	}
	return out, nil
}

func (s *secretBox) Label() string {
	return secretBoxLabel
}

func (s *secretBox) NeedsKey() bool {
	return true
}
