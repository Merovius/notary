package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"golang.org/x/crypto/ed25519"

	"github.com/Merovius/roughtime"
)

func main() {
	key, err := base64.StdEncoding.DecodeString("etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ=")
	if err != nil {
		log.Fatal(err)
	}
	m, r, err := roughtime.FetchRoughtime(&roughtime.Server{"roughtime.sandbox.google.com:2002", ed25519.PublicKey(key)})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v ± %v\n", m, r)
}
