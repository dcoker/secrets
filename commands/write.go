package commands

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"strings"

	"github.com/dcoker/secrets/algorithms"
	"github.com/dcoker/secrets/providers"
	"github.com/dcoker/secrets/store"
	"gopkg.in/alecthomas/kingpin.v2"
)

// Write implements the "write" command.
type Write struct {
	keyID *string
	name  *string
	value *string
	algo  *string
}

var (
	errNoKeySpecified = errors.New("Please specify a keyId with --key-id.")
	errMultipleKeys   = errors.New("Unable to determine what key to use because there is more " +
		"than one currently in use.")
)

// NewWrite returns a Write configured to receive parameters from kingpin.
func NewWrite(c *kingpin.CmdClause) *Write {
	write := &Write{}
	write.keyID = c.Flag("key-id",
		"The ID of the key to use. If not set, we'll pick a key that is "+
			"already in use.").Short('k').String()
	write.name = c.Arg("name", "Name of the secret.").Required().String()
	write.value = c.Arg("value", "Value of the secret.").Required().String()

	clause := c.Flag("algorithm", "Encryption algorithm. Options: "+
		strings.Join(algorithms.GetAlgorithms(), ","))
	clause = clause.Short('a')
	clause = clause.Default(algorithms.GetDefaultAlgorithm())
	write.algo = clause.Enum(algorithms.GetAlgorithms()...)
	return write
}

// Run runs the command.
func (w *Write) Run(database store.FileStore, provider providers.Provider) error {
	if len(*w.keyID) == 0 {
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
	}
	envelopeKey, err := provider.GenerateEnvelopeKey(*w.keyID)
	if err != nil {
		return err
	}

	box := algorithms.New(*w.algo)
	ciphertext, err := box.Encrypt(envelopeKey.GetPlaintext32(), []byte(*w.value))
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	value := store.Value{
		Algorithm:     box.Label(),
		KeyID:         *w.keyID,
		KeyCiphertext: base64.StdEncoding.EncodeToString(envelopeKey.Ciphertext),
		Ciphertext:    encoded,
	}
	return database.Put(*w.name, value)
}
