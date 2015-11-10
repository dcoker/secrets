package keymanager

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

const (
	kmsLabel = "kms"
)

func init() {
	registry[kmsLabel] = NewKms
}

// Kms is a KeyManager for AWS KMS.
type Kms struct {
	client *kms.KMS
}

// NewKms returns a new Kms.
func NewKms() KeyManager {
	return &Kms{kms.New(session.New())}
}

// GenerateEnvelopeKey generates an EnvelopeKey under a specific KeyID.
func (k *Kms) GenerateEnvelopeKey(keyID string, secretID string) (EnvelopeKey, error) {
	generateDataKeyInput := &kms.GenerateDataKeyInput{
		KeyId: aws.String(keyID),
		EncryptionContext: aws.StringMap(map[string]string{
			"SecretId": secretID,
		}),
		NumberOfBytes: aws.Int64(32)}
	gdko, err := k.client.GenerateDataKey(generateDataKeyInput)
	return EnvelopeKey{gdko.Plaintext, gdko.CiphertextBlob}, err
}

// Decrypt decrypts the encrypted key.
func (k *Kms) Decrypt(keyCiphertext []byte, secretID string) ([]byte, error) {
	do, err := k.client.Decrypt(&kms.DecryptInput{
		EncryptionContext: aws.StringMap(map[string]string{
			"SecretId": secretID,
		}),
		CiphertextBlob: keyCiphertext,
	})
	return do.Plaintext, err
}

// Label returns kmsLabel
func (k *Kms) Label() string {
	return kmsLabel
}
