package main

import (
	"flag"
	"io"
	"log"
	"os"
	"strings"

	"github.com/Merovius/roughtime"
	config "github.com/Merovius/roughtime/internal/config"
)

func main() {
	verify := flag.Bool("verify", false, "verify a given chain")
	serversJSON := flag.String("servers", "", "server-list to use")
	flag.Parse()

	servers, err := serverList(*serversJSON)
	if err != nil {
		log.Fatal(err)
	}

	if *verify {
		if err := roughtime.VerifyChain(os.Stdin, servers); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := roughtime.Chain(os.Stdout, servers, nil); err != nil {
		log.Fatal(err)
	}
}

func serverList(name string) (*config.ServersJSON, error) {
	r := io.Reader(strings.NewReader(defaultServers))
	if name != "" {
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	return roughtime.ReadServersJSON(r)
}

var defaultServers = `{
	"servers": [
		{
			"name": "Google",
			"publicKeyType": "ed25519",
			"publicKey": "etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ=",
			"addresses": [
				{
					"protocol": "udp",
					"address": "roughtime.sandbox.google.com:2002"
				}
			]
		},
		{
			"name": "Cloudflare",
			"publicKeyType": "ed25519",
			"publicKey": "gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo=",
			"addresses": [
				{
					"protocol": "udp",
					"address": "roughtime.cloudflare.com:2002"
				}
			]
		}
	]
}`
