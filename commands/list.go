package commands

import (
	"fmt"

	"github.com/dcoker/secrets/store"
)

// List implements the "list" command.
type List struct{}

// NewList returns a List.
// kingpin.
func NewList() *List {
	return &List{}
}

// Run runs the command.
func (r *List) Run(database store.FileStore) error {
	entries, err := database.GetAll()
	if err != nil {
		return err
	}
	for name := range entries {
		fmt.Printf("%s\n", name)
	}
	return nil
}
