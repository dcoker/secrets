package providers

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
)

// Provider represents a service that can generate envelope keys and decrypt data encrypted with
// those keys.
type Provider interface {
	GenerateEnvelopeKey(keyID string) (EnvelopeKey, error)
	Decrypt(keyMetadata []byte) ([]byte, error)
}

// Kms is a Provider for AWS KMS.
type Kms struct {
	client *kms.KMS
}

// NewKms returns a new Kms.
func NewKms() *Kms {
	return &Kms{kms.New(nil)}
}

// GenerateEnvelopeKey generates an EnvelopeKey under a specific KeyID.
func (k *Kms) GenerateEnvelopeKey(keyID string) (EnvelopeKey, error) {
	gdko, err := k.client.GenerateDataKey(&kms.GenerateDataKeyInput{KeyId: aws.String(keyID),
		NumberOfBytes: aws.Int64(32)})
	return EnvelopeKey{gdko.Plaintext, gdko.CiphertextBlob}, err
}

// Decrypt decrypts the encrypted key.
func (k *Kms) Decrypt(keyCiphertext []byte) ([]byte, error) {
	do, err := k.client.Decrypt(&kms.DecryptInput{CiphertextBlob: keyCiphertext})
	return do.Plaintext, err
}
