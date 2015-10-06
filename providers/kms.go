package providers

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
)

const (
	kmsLabel = "kms"
)

func init() {
	registry[kmsLabel] = NewKms
}

// Kms is a Provider for AWS KMS.
type Kms struct {
	client *kms.KMS
}

// NewKms returns a new Kms.
func NewKms() Provider {
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

// Label returns kmsLabel
func (k *Kms) Label() string {
	return kmsLabel
}
