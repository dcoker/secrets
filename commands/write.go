package commands

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"strings"

	"io/ioutil"

	"github.com/dcoker/secrets/algorithms"
	"github.com/dcoker/secrets/providers"
	"github.com/dcoker/secrets/store"
	"gopkg.in/alecthomas/kingpin.v2"
)

// Write implements the "write" command.
type Write struct {
	keyID       *string
	keyProvider *string
	name        *string
	fromFile    **os.File
	value       *string
	algo        *string
}

var (
	errNoKeySpecified = errors.New("Please specify a key ID with --key-id.")
	errMultipleKeys   = errors.New("Unable to determine what key to use because there is more " +
		"than one currently in use.")
	errConflictingValue = errors.New(
		"Please specify either a value in a positional argument, or use --from-file, but not both.")
	errUnsupportedProvider = errors.New("Unsupported provider.")
)

// NewWrite returns a Write configured to receive parameters from kingpin.
func NewWrite(c *kingpin.CmdClause) *Write {
	write := &Write{}
	write.keyID = c.Flag("key-id",
		"The ID of the key to use. If not set, and if all values in the specified store are "+
			"using the same key ID, that key will be used.").Short('k').String()
	write.keyProvider = c.Flag("key-provider", "Source of envelope encryption keys. Options: "+
		strings.Join(providers.GetProviders(), ", ")).
		Default(providers.GetDefaultProvider()).Short('p').Enum(providers.GetProviders()...)
	write.name = c.Arg("name", "Name of the secret.").Required().String()
	write.value = c.Arg("value", "Value of the secret.").String()
	write.fromFile = c.Flag("from-file", "Read the secret from FILE instead "+
		"of the command line.").PlaceHolder("FILE").Short('i').File()
	write.algo = c.Flag("algorithm", "Encryption algorithm. Options: "+
		strings.Join(algorithms.GetAlgorithms(), ", ")).
		Short('a').
		Default(algorithms.GetDefaultAlgorithm()).
		Enum(algorithms.GetAlgorithms()...)

	return write
}

// Run runs the command.
func (w *Write) Run(database store.FileStore) error {
	provider := providers.New(*w.keyProvider)
	if provider == nil {
		return errUnsupportedProvider
	}
	plaintext, err := w.choosePlaintext()
	if err != nil {
		return err
	}
	if err := w.chooseKeyID(database); err != nil {
		return err
	}

	envelopeKey, err := provider.GenerateEnvelopeKey(*w.keyID)
	if err != nil {
		return err
	}

	box := algorithms.New(*w.algo)
	ciphertext, err := box.Encrypt(envelopeKey.GetPlaintext32(), plaintext)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	value := store.Value{
		Algorithm:     box.Label(),
		KeyID:         *w.keyID,
		KeyProvider:   provider.Label(),
		KeyCiphertext: base64.StdEncoding.EncodeToString(envelopeKey.Ciphertext),
		Ciphertext:    encoded,
	}
	return database.Put(*w.name, value)
}

func (w *Write) choosePlaintext() ([]byte, error) {
	var plaintext []byte
	var err error
	if *w.fromFile != nil && len(*w.value) > 0 {
		return nil, errConflictingValue
	}
	if *w.fromFile != nil {
		plaintext, err = ioutil.ReadAll(*w.fromFile)
		if err != nil {
			return nil, err
		}
	} else {
		plaintext = []byte(*w.value)
	}
	return plaintext, nil
}

func (w *Write) chooseKeyID(database store.FileStore) error {
	if len(*w.keyID) != 0 {
		return nil
	}
	existingKeys, err := database.GetKeyIds()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(existingKeys) > 1 {
		return errMultipleKeys
	} else if len(existingKeys) == 0 {
		return errNoKeySpecified
	}
	for keyID := range existingKeys {
		fmt.Fprintf(os.Stderr, "Using existing key %s\n", keyID)
		*w.keyID = keyID
		break
	}
	return nil
}
