package rainspub

import (
	"rains/rainslib"
	"time"

	"golang.org/x/crypto/ed25519"
)

//config contains configurations for publishing a rains zone file
var config rainpubConfig

//zonePrivateKey is used to sign all information about this zone
var zonePrivateKey ed25519.PrivateKey

//parser is used to extract assertions from a rains zone file.
var parser rainslib.ZoneFileParser

//signatureEncoder is used to encode a section such that it can be signed
var signatureEncoder rainslib.SignatureFormatEncoder

//msgParser is used to encode the generated zone such that it can be pushed to the rainsd server
var msgParser rainslib.RainsMsgParser

//rainpubConfig lists configurations for publishing zone information
type rainpubConfig struct {
	//AssertionValidity defines the time when an assertion (except a delegation assertion) is valid starting from the time it is signed
	AssertionValidSince time.Duration //in hours
	//DelegationValidity defines the time when a delegation assertion is valid starting from the time it is signed
	DelegationValidSince time.Duration //in hours
	//ShardValidity defines the time when a shard is valid starting from the time it is signed
	ShardValidSince time.Duration //in hours
	//ZoneValidity defines the time when a zone is valid starting from the time it is signed
	ZoneValidSince time.Duration //in hours
	//AssertionValidity defines the time until an assertion (except a delegation assertion) is valid starting from the time it is signed
	AssertionValidUntil time.Duration //in hours
	//DelegationValidity defines the time until a delegation assertion is valid starting from the time it is signed
	DelegationValidUntil time.Duration //in hours
	//ShardValidity defines the time until a shard is valid starting from the time it is signed
	ShardValidUntil time.Duration //in hours
	//ZoneValidity defines the time until a zone is valid starting from the time it is signed
	ZoneValidUntil time.Duration //in hours
	//MaxAssertionsPerShard the maximal number of assertions per shard. Currently independent of assertion's internal size
	MaxAssertionsPerShard uint
	//ServerAddresses of the rainsd servers to which rainspub is pushing zone file information
	ServerAddresses []rainslib.ConnInfo
	//ZoneFilePath is the location of the rains zone file
	ZoneFilePath string
	//ZonePrivateKeyPath is the location of the zone's privateKey
	//TODO CFE move this key into an airgapped device.
	ZonePrivateKeyPath string
}
