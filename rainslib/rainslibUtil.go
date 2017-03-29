package rainslib

import (
	"crypto/rand"

	log "github.com/inconshreveable/log15"
)

//GenerateToken generates a new unique Token
func GenerateToken() Token {
	token := [16]byte{}
	_, err := rand.Read(token[:])
	if err != nil {
		log.Warn("Error during random token generation")
	}
	return Token(token)
}
