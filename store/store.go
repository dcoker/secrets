package store

import (
	"encoding/base64"
	"errors"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

var errNotFound = errors.New("name not found")

// FileStore stores an EntryMap in a YAML file on local disk.
type FileStore string

// EntryMap represents the contents of the file.
type EntryMap map[string]Value

// NewFileStore constructs a FileStore for a specific filename.
func NewFileStore(filename string) FileStore {
	return FileStore(filename)
}

// Get a value.
func (f FileStore) Get(name string) (Value, error) {
	entries, err := f.GetAll()
	if err != nil {
		return Value{}, err
	}
	value, present := entries[name]
	if !present {
		return Value{}, errNotFound
	}
	return value, nil
}

// Put a value.
func (f FileStore) Put(name string, value Value) error {
	entries, err := f.GetAll()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	entries[name] = value

	output, err := yaml.Marshal(entries)
	if err != nil {
		return err
	}

	// poor attempt at atomic file write
	tempfile := string(f) + ".tmp"
	if err := ioutil.WriteFile(tempfile, output, 0644); err != nil {
		return err
	}
	return os.Rename(tempfile, string(f))
}

// GetAll returns all of the entries in the file.
func (f FileStore) GetAll() (EntryMap, error) {
	contents, err := ioutil.ReadFile(string(f))
	entries := make(EntryMap)
	if err != nil {
		return entries, err
	}
	return entries, yaml.Unmarshal(contents, entries)
}

// GetKeyIds returns a histogram of occurrences of key IDs.
func (f FileStore) GetKeyIds() (map[string]int, error) {
	keyIds := make(map[string]int)
	entries, err := f.GetAll()
	if err != nil {
		return keyIds, err
	}
	for _, v := range entries {
		keyIds[v.KeyID]++
	}
	return keyIds, nil
}

// Value is one entry in the file.
type Value struct {
	// KeyID of the key that this value is encrypted under. This identifies which key the
	// Provider should use.
	KeyID string `yaml:"key_id"`
	// KeyCiphertext is the encryption key that Ciphertext is encrypted with, but encrypted with a
	// key that only the Provider has.
	KeyCiphertext string `yaml:"key_ciphertext"`
	// Algorithm used to populate Ciphertext.
	Algorithm string `yaml:"algorithm"`
	// Ciphertext is the plaintext encrypted with the ephemeral key.
	Ciphertext string `yaml:"ciphertext"`
}

// GetKeyCiphertext returns the base64-decoded encrypted key.
func (v *Value) GetKeyCiphertext() ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(v.KeyCiphertext)
	return decoded, err
}

// GetCiphertext returns the base64-decoded ciphertext.
func (v *Value) GetCiphertext() ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(v.Ciphertext)
	return decoded, err
}
