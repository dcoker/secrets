package main

import (
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/dcoker/secrets/commands"
	"github.com/dcoker/secrets/store"
	"gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	app := kingpin.New("secrets", string(MustAsset("docs/usage.txt")))
	filename := app.Flag("filename", "Name of file to store encrypted secrets in.").
		PlaceHolder("FILE").
		Short('f').
		Required().
		String()
	readSpec := app.Command("read", "Read a secret.")
	writeSpec := app.Command("write", "Write a secret.")
	listSpec := app.Command("list", "List secrets.")

	readCommand := commands.NewRead(readSpec)
	writeCommand := commands.NewWrite(writeSpec)
	listCommand := commands.NewList()

	behavior := kingpin.MustParse(app.Parse(os.Args[1:]))
	filestore := store.NewFileStore(*filename)
	var err error
	switch behavior {
	case readSpec.FullCommand():
		err = readCommand.Run(filestore)
	case writeSpec.FullCommand():
		err = writeCommand.Run(filestore)
	case listSpec.FullCommand():
		err = listCommand.Run(filestore)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		if awsErr, ok := err.(awserr.Error); ok {
			switch awsErr.Code() {
			case "MissingRegion":
				fmt.Fprintf(os.Stderr, "Hint: Check or set the AWS_REGION environment variable.\n")
			case "ExpiredTokenException":
				fmt.Fprintf(os.Stderr, "Hint: Check or set the AWS_PROFILE environment variable.\n")
			case "InvalidCiphertextException":
				fmt.Fprintf(os.Stderr, "Hint: key_ciphertext may be corrupted.\n")
			}
		}
		os.Exit(1)
	}
}
