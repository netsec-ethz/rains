package main

import (
	"encoding/pem"
	"fmt"
	"log"
	"strings"

	"github.com/netsec-ethz/rains/internal/pkg/keyManager"
	flag "github.com/spf13/pflag"
)

var keyName = flag.StringP("name", "n", "", "prefix of the file name where the key is loaded from or will be stored to. (default \"\")")
var algo = flag.StringP("algo", "a", "ed25519", `defines the algorithm which is used in key generation. 
Supported algorithms are: ed25519`)
var phase = flag.Int("phase", 0, "defines the key phase for which a key is generated. (default 0)")
var description = flag.StringP("description", "d", "", `allows to store an arbitrary 
string value with the key. It can e.g. be used to store the information in which zone and context 
the key pair is used. The default is the empty string. (default \"\")`)
var pwd = flag.String("pwd", "", "password to encrypt or decrypt a private key. (default \"\")")

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
		keys, err := keyManager.LoadPublicKeys(path)
		if err != nil {
			log.Fatalf("Was not able to load public keys: %v", err)
		}
		val := []string{}
		for _, key := range keys {
			val = append(val, fmt.Sprintf("%s", pem.EncodeToMemory(key)))
		}
		fmt.Println(strings.Join(val, "\n"))
	case "generate", "gen", "g":
		err := keyManager.GenerateKey(path, *keyName, *description, *algo, *pwd, *phase)
		if err != nil {
			log.Fatalf("Was not able to generate key pair: %v", err)
		}
	case "decrypt", "d":
		block, err := keyManager.DecryptKey(path, *keyName, *pwd)
		if err != nil {
			log.Fatalf("Was not able to decrypt private key: %v", err)
		}
		fmt.Printf("%s", pem.EncodeToMemory(block))
	default:
		log.Fatal("Unknown command")
	}
}
