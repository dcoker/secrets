package store

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStore_Empty(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "TestStore")
	defer os.Remove(tmpfile.Name())
	assert.NoError(t, err)
	store := NewFileStore(tmpfile.Name())
	contents, err := store.GetAll()
	assert.NoError(t, err)
	assert.Len(t, contents, 0)
}

func TestStore_Lifecycle(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "TestStore")
	defer os.Remove(tmpfile.Name())
	assert.NoError(t, err)
	store := NewFileStore(tmpfile.Name())
	k1put := Value{
		Algorithm:     "plaintext",
		KeyID:         "key_id",
		KeyCiphertext: "ciphertext",
		Ciphertext:    "ciphertext",
	}
	if err := store.Put("k1", k1put); err != nil {
		assert.NoError(t, err)
	}
	entries, err := store.GetAll()
	assert.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, k1put, entries["k1"])
	k1actual, err := store.Get("k1")
	assert.NoError(t, err)
	assert.Equal(t, entries["k1"], k1actual)

	k2put := Value{
		Algorithm:     "p",
		KeyID:         "k",
		KeyCiphertext: "ct",
		Ciphertext:    "c",
	}
	if err := store.Put("k2", k2put); err != nil {
		assert.NoError(t, err)
	}
	entries, err = store.GetAll()
	assert.NoError(t, err)
	assert.Len(t, entries, 2)
	assert.Equal(t, k1put, entries["k1"])
	assert.Equal(t, k2put, entries["k2"])

	keyIds, err := store.GetKeyIds()
	assert.NoError(t, err)
	assert.Equal(t, 1, keyIds["k"])
	assert.Equal(t, 1, keyIds["key_id"])
}

func TestStore_fileDoesNotExist(t *testing.T) {
	store := NewFileStore("does_not_exist")
	_, err := store.GetAll()
	assert.True(t, os.IsNotExist(err))
}

func TestStore_writingCreatesFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestStore")
	assert.NoError(t, err)
	defer os.RemoveAll(dir)
	filename := path.Join(dir, "secrets.yml")

	store := NewFileStore(filename)
	assert.NoError(t, store.Put("k1", Value{}))
	contents, err := store.GetAll()
	assert.NoError(t, err)
	assert.Len(t, contents, 1)
}
