package section

import (
	"math"
	"time"

	log "github.com/inconshreveable/log15"
)

func UpdateValidity(validSince, validUntil, oldValidSince, oldValidUntil int64,
	maxValidity time.Duration) (int64, int64) {
	if oldValidSince == 0 {
		oldValidSince = math.MaxInt64
	}
	if validSince < oldValidSince {
		if validSince > time.Now().Add(maxValidity).Unix() {
			oldValidSince = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidSince exceeded maxValidity", "oldValidSince", oldValidSince,
				"newValidSince", validSince, "maxValidity", maxValidity)
		} else {
			oldValidSince = validSince
		}
	}
	if validUntil > oldValidUntil {
		if validUntil > time.Now().Add(maxValidity).Unix() {
			oldValidUntil = time.Now().Add(maxValidity).Unix()
			log.Warn("newValidUntil exceeded maxValidity", "oldValidSince", oldValidSince,
				"newValidSince", validSince, "maxValidity", maxValidity)
		} else {
			oldValidUntil = validUntil
		}
	}
	return oldValidSince, oldValidUntil
}
