package main

import (
	"encoding/pem"
	"fmt"
	"log"

	"github.com/netsec-ethz/rains/internal/pkg/keyManager"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "keyManager",
	Short: "keyManager manages public private key pairs for the RAINS infrastructure",
	Long: `keyManager is a tool for managing public private key pairs for the RAINS infrastructure from the
command line. It offers key generation for all algorithms supported by RAINS and stores the keys pem
encoded. The private key is encrypted using aes before being pem encoded. The aes key is generated
from a user provided password. Given the name of the key and the correct password, the keyManager
decrypts the private key and prints it pem encoded.`,
}

var genCmd = &cobra.Command{
	Use:     "gen [PATH]",
	Aliases: []string{"g"},
	Short:   "Gen creates and stores a new public-private key pair",
	Long: `Generate first creates a new public-private key pair according to the provided algorithm. It
then encrypts the private key with the provided password. Lastly, it pem encodes the private and
public key separately and stores them at the provided PATH (default current folder). The file 
prefix corresponds to the provided name followed by _sec.pem or _pub.pem (for private or public key).`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyManager.GenerateKey(path, name, description, algo, pwd, phase)
	},
}

var loadCmd = &cobra.Command{
	Use:     "load [PATH]",
	Aliases: []string{"l"},
	Short:   "Prints all public keys stored in a folder",
	Long:    `Prints all public keys stored at PATH (default current folder).`,
	Args:    cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(keyManager.LoadPublicKeys(path))
	},
}

var decryptCmd = &cobra.Command{
	Use:     "decrypt [PATH]",
	Aliases: []string{"d"},
	Short:   "Decrypts and prints a private key",
	Long: `Decrypt loads the pem encoded private key at PATH (default current folder) 
corresponding to name. It then encrypts the private key with the user 
provided password and prints the decrypted key pem encoded to stdout.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		block := keyManager.DecryptKey(path, name, pwd)
		if block != nil {
			log.Fatal("Was not able to decrypt private key")
		}
		fmt.Printf("%s", pem.EncodeToMemory(block))
	},
}

var name string
var algo string
var phase int
var description string
var pwd string
var path string

func init() {
	rootCmd.AddCommand(genCmd, loadCmd, decryptCmd)

	//gen flags
	genCmd.Flags().StringVarP(&name, "name", "n", "", "prefix of the file name where the key is loaded from or will be stored to. (default \"\")")
	genCmd.Flags().StringVarP(&algo, "algo", "a", "ed25519", `defines the algorithm which is used in key generation. 
Supported algorithms are: ed25519`)
	genCmd.Flags().IntVarP(&phase, "phase", "p", 0, "defines the key phase for which a key is generated. (default 0)")
	genCmd.Flags().StringVarP(&description, "description", "d", "",
		`allows to store an arbitrary string value with the key. 
It can e.g. be used to store the information in which 
zone and context the key pair is used. (default "")`)
	genCmd.Flags().StringVar(&pwd, "pwd", "", "password to encrypt or decrypt a private key. (default \"\")")

	//decrypt flags
	decryptCmd.Flags().StringVarP(&name, "name", "n", "", "prefix of the file name where the key is loaded from or will be stored to. (default \"\")")
	decryptCmd.Flags().StringVar(&pwd, "pwd", "", "password to encrypt or decrypt a private key. (default \"\")")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
