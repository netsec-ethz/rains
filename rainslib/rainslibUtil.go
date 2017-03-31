package rainslib

import (
	"crypto/rand"

	"fmt"

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

//GenerateAssertionCacheKey creates string key used in cache lookups
func GenerateAssertionCacheKey(zone, name, assertionType string) string {
	return fmt.Sprintf("%s:%s:%s", zone, name, assertionType)
}

//GenerateZoneKeyCacheKey creates string key used in cache lookups
func GenerateZoneKeyCacheKey(zone, keyAlgo string) string {
	return fmt.Sprintf("%s:%s", zone, keyAlgo)
}
