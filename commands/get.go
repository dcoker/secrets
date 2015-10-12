package commands

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/dcoker/secrets/algorithms"
	"github.com/dcoker/secrets/keymanager"
	"github.com/dcoker/secrets/store"
	"gopkg.in/alecthomas/kingpin.v2"
)

// Get implements the "get" command.
type Get struct {
	format  *string
	name    *string
	writeTo *string
}

// NewGet returns a Get configured to receive parameters from kingpin.
func NewGet(c *kingpin.CmdClause) *Get {
	return &Get{
		name: c.Arg("name", "Name of the secret to read.").Required().String(),
		writeTo: c.Flag("output", "Write to FILE instead of stdout.").
			PlaceHolder("FILE").
			Short('o').
			String(),
	}
}

// Run runs the command.
func (r *Get) Run(database store.FileStore) error {
	value, err := database.Get(*r.name)
	if err != nil {
		return err
	}
	algo, err := algorithms.New(value.Algorithm)
	if err != nil {
		return err
	}
	var decryptionKeyArray [32]byte
	if algo.NeedsKey() {
		keyManager, err := keymanager.New(value.KeyManager)
		if err != nil {
			return err
		}

		keyCiphertext, err2 := value.GetKeyCiphertext()
		if err2 != nil {
			return err2
		}
		keyPlaintext, err2 := keyManager.Decrypt(keyCiphertext)
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

	if len(*r.writeTo) > 0 {
		return ioutil.WriteFile(*r.writeTo, plaintext, 0644)
	}

	fmt.Printf("%s", plaintext)
	if !bytes.HasSuffix(plaintext, []byte{'\n'}) {
		fmt.Printf("\n")
	}
	return nil
}
