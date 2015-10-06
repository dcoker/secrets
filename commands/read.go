package commands

import (
	"fmt"

	"bytes"

	"io/ioutil"

	"errors"

	"github.com/dcoker/secrets/algorithms"
	"github.com/dcoker/secrets/providers"
	"github.com/dcoker/secrets/store"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	errUnsupportedAlgorithm = errors.New("read: unsupported algorithm")
)

// Read implements the "read" command.
type Read struct {
	format  *string
	name    *string
	writeTo *string
}

// NewRead returns a Read configured to receive parameters from kingpin.
func NewRead(c *kingpin.CmdClause) *Read {
	return &Read{
		name: c.Arg("name", "Name of the secret to read.").Required().String(),
		writeTo: c.Flag("output", "Write to FILE instead of stdout.").
			PlaceHolder("FILE").
			Short('o').
			String(),
	}
}

// Run runs the command.
func (r *Read) Run(database store.FileStore) error {
	value, err := database.Get(*r.name)
	if err != nil {
		return err
	}
	algo := algorithms.New(value.Algorithm)
	if algo == nil {
		return errUnsupportedAlgorithm
	}
	provider := providers.New(value.KeyProvider)
	if provider == nil {
		return errUnsupportedProvider
	}
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

	if len(*r.writeTo) > 0 {
		return ioutil.WriteFile(*r.writeTo, plaintext, 0644)
	}

	fmt.Printf("%s", plaintext)
	if !bytes.HasSuffix(plaintext, []byte{'\n'}) {
		fmt.Printf("\n")
	}
	return nil
}
