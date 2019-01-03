package main

import (
	"flag"
)

var keyPath = flag.String("path", "", "Path where the keys are or will be stored.")
var action = flag.String("action", "load", `load or l prints all public keys stored at path. 
generate, gen or g generates a new public-private, stores them at path and prints the public key`)
var algo = flag.String("algo", "ed25519", "Algorithm used to generate key")
var phase = flag.String("phase", "0", "Key phase of the generated key")
var description = flag.String("d", "", "description added when a new key pair is generated")
var pwd = flag.String("pwd", "", "password to decrypt stored private keys or used to encrypt a newly generated key pair")

func main() {
	flag.Parse()
}
