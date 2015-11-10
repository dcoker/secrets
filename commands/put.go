package commands

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"strings"

	"io/ioutil"

	"github.com/dcoker/secrets/algorithms"
	"github.com/dcoker/secrets/keymanager"
	"github.com/dcoker/secrets/store"
	"gopkg.in/alecthomas/kingpin.v2"
)

// Put implements the "put" command.
type Put struct {
	keyID      *string
	keyManager *string
	name       *string
	fromFile   **os.File
	value      *string
	algo       *string
}

var (
	errNoKeySpecified = errors.New("Please specify a key ID with --key-id.")
	errMultipleKeys   = errors.New("Unable to determine what key to use because there is more " +
		"than one currently in use.")
	errConflictingValue = errors.New(
		"Please specify either a secret in a positional argument, or use --from-file, " +
			"but not both.")
)

// NewPut returns a Put configured to receive parameters from kingpin.
func NewPut(c *kingpin.CmdClause) *Put {
	write := &Put{}
	write.keyID = c.Flag("key-id",
		"The ID of the key to use. If not set, and if all values in the specified store are "+
			"using the same key ID, that key will be used.").Short('k').String()
	write.keyManager = c.Flag("key-manager", "Source of envelope encryption keys. Options: "+
		strings.Join(keymanager.GetKeyManagers(), ", ")).
		Default(keymanager.GetDefaultKeyManager()).Short('p').Enum(keymanager.GetKeyManagers()...)
	write.name = c.Arg("name", "Name of the secret.").Required().String()
	write.value = c.Arg("secret", "Value of the secret.").String()
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
func (w *Put) Run(database store.FileStore) error {
	var value store.Value
	algo, err := algorithms.New(*w.algo)
	if err != nil {
		return err
	}
	value.Algorithm = algo.Label()

	var envelopeKey keymanager.EnvelopeKey
	if algo.NeedsKey() {
		keyManager, err := keymanager.New(*w.keyManager)
		if err != nil {
			return err
		}
		value.KeyManager = keyManager.Label()

		if err := w.chooseKeyID(database); err != nil {
			return err
		}
		value.KeyID = *w.keyID

		envelopeKey, err = keyManager.GenerateEnvelopeKey(*w.keyID, *w.name)
		if err != nil {
			return err
		}
		value.KeyCiphertext = base64.StdEncoding.EncodeToString(envelopeKey.Ciphertext)
	}

	plaintext, err := w.choosePlaintext()
	if err != nil {
		return err
	}

	ciphertext, err := algo.Encrypt(envelopeKey.GetPlaintext32(), plaintext)
	if err != nil {
		return err
	}
	value.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)

	return database.Put(*w.name, value)
}

func (w *Put) choosePlaintext() ([]byte, error) {
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

func (w *Put) chooseKeyID(database store.FileStore) error {
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
