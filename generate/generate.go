package main

import (
	"fmt"
	"os"

	"github.com/dedis/crypto/ed25519"
	"github.com/dedis/crypto/random"
)

func main() {
	fmt.Println("generate.go - generate ed25519 private key and write into file")
	fmt.Println("WARNING: Do NOT USE this private key for anything else than playing " +
		"with cosic. It's a reduced private key and it only contains the private part " +
		"and not the public")

	if len(os.Args) != 2 {
		errExit("Usage: go run generate.go <private key file>")
	}

	suite := ed25519.NewAES128SHA256Ed25519(false)
	private := suite.NewKey(random.Stream)

	data, err := private.MarshalBinary()
	if err != nil {
		errExit("Could not marshal private key: %v", err)
	}

	f, err := os.Create(os.Args[1])
	if err != nil {
		errExit("%v", err)
	}
	defer f.Close()

	n, err := f.Write(data)
	if err != nil {
		errExit("%v", err)
	} else if n != len(data) {
		errExit("Only wrote %d/%d bytes ... ><", n, len(data))
	}

	fmt.Printf("\nPrivate key written in %s. Good bye!\n", os.Args[1])
}

func errExit(format string, args ...interface{}) {
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, format+"\n", args)
	} else {
		fmt.Fprintf(os.Stderr, format+"\n")
	}
	os.Exit(1)
}
