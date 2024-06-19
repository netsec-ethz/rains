package token

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"

	log "github.com/inconshreveable/log15"
)

// Token identifies a message
type Token [16]byte

// String implements Stringer interface
func (t Token) String() string {
	return hex.EncodeToString(t[:])
}

// Compare returns an integer comparing two Tokens lexicographically. The result will be 0 if
// a==b, -1 if a < b, and +1 if a > b. A nil argument is equivalent to an empty slice
func Compare(a, b Token) int {
	return bytes.Compare(a[:], b[:])
}

// New generates a new unique Token
func New() Token {
	token := [16]byte{}
	_, err := rand.Read(token[:])
	if err != nil {
		log.Warn("Error during random token generation", "error", err)
	}
	return Token(token)
}
