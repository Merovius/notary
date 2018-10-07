package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ed25519"

	"github.com/Merovius/roughtime"
)

func main() {
	verify := flag.Bool("verify", false, "verify a given chain")
	flag.Parse()

	f, err := os.Open("servers.json")
	if err != nil {
		log.Fatal(err)
	}
	servers, err := roughtime.ReadServersJSON(f)
	if err != nil {
		log.Fatal(err)
	}
	f.Close()

	if *verify {
		if err := roughtime.VerifyChain(os.Stdin, servers); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := roughtime.Chain(os.Stdout, servers, nil); err != nil {
		log.Fatal(err)
	}

	return
	key, err := base64.StdEncoding.DecodeString("etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ=")
	if err != nil {
		log.Fatal(err)
	}
	m, r, err := roughtime.FetchRoughtime(&roughtime.Server{"roughtime.sandbox.google.com:2002", ed25519.PublicKey(key)}, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v ± %v\n", m, r)
}
