package main

import (
	"flag"
	"log"

	"github.com/netsec-ethz/rains/internal/pkg/keyManager"
)

const (
	public  = "PublicKey"
	private = "PrivateKey"
)

var keyPath = flag.String("path", "", "Path where the keys are or will be stored.")
var keyName = flag.String("name", "", "Name determines the prefix of the key pair's file name")
var action = flag.String("action", "load", `load or l prints all public keys stored at path. 
generate, gen or g generates a new public-private, stores them at path and prints the public key.
remove or r deletes the keypair at keyPath with keyName. decrypt or d decrypts the private key 
specified by keyName using pwd and printing it.`)
var algo = flag.String("algo", "ed25519", "Algorithm used to generate key")
var phase = flag.Int("phase", 0, "Key phase of the generated key")
var description = flag.String("d", "", "description added when a new key pair is generated")
var pwd = flag.String("pwd", "", "password to used to encrypt a newly generated key pair")

func main() {
	flag.Parse()
	switch *action {
	case "load", "l":
		keyManager.LoadPublicKeys(*keyPath)
	case "generate", "gen", "g":
		keyManager.GenerateKey(*keyPath, *keyName, *description, *algo, *pwd, *phase)
	case "remove", "r":
		keyManager.RemoveKey(*keyPath, *keyName)
	case "decrypt", "d":
		keyManager.DecryptKey(*keyPath, *keyName, *pwd)
	default:
		log.Fatal("Unknown action")
	}
}
