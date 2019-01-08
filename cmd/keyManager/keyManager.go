package main

import (
	"log"

	"github.com/netsec-ethz/rains/internal/pkg/keyManager"
	flag "github.com/spf13/pflag"
)

const (
	public  = "PublicKey"
	private = "PrivateKey"
)

var keyPath = flag.StringP("path", "p", "", "Path where the keys are or will be stored.")
var keyName = flag.StringP("name", "n", "", "Name determines the prefix of the key pair's file name")
var algo = flag.StringP("algo", "a", "ed25519", "Algorithm used to generate key")
var phase = flag.Int("phase", 0, "Key phase of the generated key")
var description = flag.StringP("description", "d", "", "description added when a new key pair is generated")
var pwd = flag.String("pwd", "", "password to used to encrypt a newly generated key pair")

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		log.Fatal("Please provide a command")
	}
	if len(flag.Args()) > 1 {
		log.Fatal("Too many arguments")
	}
	switch flag.Arg(0) {
	case "load", "l":
		keyManager.LoadPublicKeys(*keyPath)
	case "generate", "gen", "g":
		keyManager.GenerateKey(*keyPath, *keyName, *description, *algo, *pwd, *phase)
	case "decrypt", "d":
		keyManager.DecryptKey(*keyPath, *keyName, *pwd)
	default:
		log.Fatal("Unknown command")
	}
}
