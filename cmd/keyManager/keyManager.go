package main

import (
	"encoding/pem"
	"fmt"
	"log"

	"github.com/netsec-ethz/rains/internal/pkg/keyManager"
	flag "github.com/spf13/pflag"
)

var keyName = flag.StringP("name", "n", "", "prefix of the file name where the key is loaded from or will be stored to.")
var algo = flag.StringP("algo", "a", "ed25519", `defines the algorithm which is used in key generation. 
The default is ed25519. Supported algorithms are: ed25519`)
var phase = flag.Int("phase", 0, "defines the key phase for which a key is generated. The default is 0")
var description = flag.StringP("description", "d", "", `allows to store an arbitrary 
string value with the key. It can e.g. be used to store the information in which zone and context 
the key pair is used. The default is the empty string.`)
var pwd = flag.String("pwd", "", "states the password to encrypt or decrypt a private key. The default is the empty string.")

func main() {
	flag.Parse()
	path := ""
	cmd := ""
	switch flag.NArg() {
	case 0:
		log.Fatal("Please provide a command and a path")
	case 1:
		cmd = flag.Arg(0)
	case 2:
		cmd = flag.Arg(0)
		path = flag.Arg(1)
	default:
		log.Fatal("Too many arguments")
	}

	switch cmd {
	case "load", "l":
		fmt.Println(keyManager.LoadPublicKeys(path))
	case "generate", "gen", "g":
		keyManager.GenerateKey(path, *keyName, *description, *algo, *pwd, *phase)
	case "decrypt", "d":
		block := keyManager.DecryptKey(path, *keyName, *pwd)
		if block != nil {
			log.Fatal("Was not able to decrypt private key")
		}
		fmt.Printf("%s", pem.EncodeToMemory(block))
	default:
		log.Fatal("Unknown command")
	}
}
