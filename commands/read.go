package commands

import (
	"fmt"

	"github.com/dcoker/secrets/algorithms"
	"github.com/dcoker/secrets/providers"
	"github.com/dcoker/secrets/store"
	"gopkg.in/alecthomas/kingpin.v2"
)

// Read implements the "read" command.
type Read struct {
	format *string
	name   *string
}

// NewRead returns a Read configured to receive parameters from kingpin.
func NewRead(c *kingpin.CmdClause) *Read {
	return &Read{
		name: c.Arg("name", "Name of the secret to read.").Required().String(),
	}
}

// Run runs the command.
func (r *Read) Run(database store.FileStore, provider providers.Provider) error {
	value, err := database.Get(*r.name)
	if err != nil {
		return err
	}
	algo := algorithms.New(value.Algorithm)
	var decryptionKeyArray [32]byte
	if algo.NeedsKey() {
		keyCiphertext, err2 := value.GetKeyCiphertext()
		if err2 != nil {
			return err2
		}
		keyPlaintext, err2 := provider.Decrypt(keyCiphertext)
		if err2 != nil {
			return err2
		}
		copy(decryptionKeyArray[:], keyPlaintext)
	}
	decoded, err := value.GetCiphertext()
	if err != nil {
		return err
	}
	plaintext, err := algo.Decrypt(&decryptionKeyArray, decoded)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", plaintext)
	return nil
}
