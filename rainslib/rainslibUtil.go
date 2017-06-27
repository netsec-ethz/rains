package rainslib

import (
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"os"
	"time"

	log "github.com/inconshreveable/log15"
	"golang.org/x/crypto/ed25519"
)

func init() {
	gob.Register(PublicKey{})
	gob.RegisterName("ed25519.PublicKey", ed25519.PublicKey{})
}

//GenerateToken generates a new unique Token
func GenerateToken() Token {
	token := [16]byte{}
	_, err := rand.Read(token[:])
	if err != nil {
		log.Warn("Error during random token generation", "error", err)
	}
	return Token(token)
}

//Save stores the object to the file located at the specified path gob encoded.
func Save(path string, object interface{}) error {
	file, err := os.Create(path)
	defer file.Close()
	if err == nil {
		encoder := gob.NewEncoder(file)
		encoder.Encode(object)
	}
	return err
}

//Load fetches the gob encoded object from the file located at path
func Load(path string, object interface{}) error {
	file, err := os.Open(path)
	defer file.Close()
	if err != nil {
		log.Error("Was not able to open file", "path", path, "error", err)
		return err
	}
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(object)
	if err != nil {
		log.Error("Was not able to decode file.", "path", path, "error", err)
	}
	return err
}

//UpdateSectionValidity updates the validity of the section according to the signature validity and the publicKey validity used to verify this signature
func UpdateSectionValidity(section MessageSectionWithSig, pkeyValidSince, pkeyValidUntil, sigValidSince, sigValidUntil int64, maxVal MaxCacheValidity) {
	if section != nil {
		var maxValidity time.Duration
		switch section.(type) {
		case *AssertionSection:
			maxValidity = maxVal.AssertionValidity
		case *ShardSection:
			maxValidity = maxVal.ShardValidity
		case *ZoneSection:
			maxValidity = maxVal.ZoneValidity
		case *AddressAssertionSection:
			maxValidity = maxVal.AddressAssertionValidity
		case *AddressZoneSection:
			maxValidity = maxVal.AddressZoneValidity
		default:
			log.Warn("Not supported section", "type", fmt.Sprintf("%T", section))
			return
		}
		if pkeyValidSince < sigValidSince {
			if pkeyValidUntil < sigValidUntil {
				section.UpdateValidity(sigValidSince, pkeyValidUntil, maxValidity)
			} else {
				section.UpdateValidity(sigValidSince, sigValidUntil, maxValidity)
			}

		} else {
			if pkeyValidUntil < sigValidUntil {
				section.UpdateValidity(pkeyValidSince, pkeyValidUntil, maxValidity)
			} else {
				section.UpdateValidity(pkeyValidSince, sigValidUntil, maxValidity)
			}
		}
	}
}
