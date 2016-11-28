package main

import (
	"fmt"
	"os"

	"github.com/dedis/cothority/app/lib/config"
	"github.com/dedis/cothority/network"
	"github.com/dedis/crypto/ed25519"
	"github.com/dedis/crypto/random"
)

func main() {
	fmt.Println("generate.go - generate ed25519 private key and write into file")
	fmt.Println("WARNING: Do NOT USE this private key for anything else than playing " +
		"with cosic. It's a reduced private key and it only contains the private part " +
		"and not the public")

	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: go run generate.go <private key file> <port>\n")
		fmt.Fprintf(os.Stderr, "       port is the address to generate the group.toml file\n")
		fmt.Fprintf(os.Stderr, "       priv key file is the file where the private key is written\n")
		os.Exit(1)
	}

	suite := ed25519.NewAES128SHA256Ed25519(false)
	private := suite.NewKey(random.Stream)
	public := suite.Point().Mul(nil, private)
	address := network.NewTCPAddress("0.0.0.0:" + os.Args[2])

	stoml := config.NewServerToml(suite, public, address)

	writeToFile("group.toml", []byte(stoml.String()))
	fmt.Printf("\nGroup toml written in 'group.toml'\n")

	data, err := private.MarshalBinary()
	if err != nil {
		errExit("Could not marshal private key: %v", err)
	}

	writeToFile(os.Args[1], data)

	fmt.Printf("Private key written in %s. Good bye!\n", os.Args[1])
}

func writeToFile(name string, data []byte) {
	f, err := os.Create(name)
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
}

func errExit(format string, args ...interface{}) {
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, format+"\n", args)
	} else {
		fmt.Fprintf(os.Stderr, format+"\n")
	}
	os.Exit(1)
}
