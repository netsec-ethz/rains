package rainspub

import (
	"time"

	"github.com/netsec-ethz/rains/rainslib"
)

//config holds the configuration of the current invocation of rains publisher.
var config Config

//parser is used to extract assertions from a rains zone file.
var parser rainslib.ZoneFileParser

//signatureEncoder is used to encode signatures
var signatureEncoder rainslib.SignatureFormatEncoder

//subordinateDelegations is a list of all subordinate zones and the delegation schedule with them.
var subordinateDelegations []delegationInfo

//keyPhaseToPath maps the keyphase to the path leading to the private key of this keyphase
var keyPhaseToPath map[int]string

//delegationInfo stores meta data about a delegation issuing schedule for this zone's subordinates.
type delegationInfo struct {
	Delegation rainslib.AssertionSection //Delegation information
	Start      time.Time                 //Start time of delegation to subordinate
	Interval   time.Duration             //Time period after which the next delegation will be issued
}

//Config lists configurations for publishing zone information, see zonepub flag description for
//detail.
type Config struct {
	ZonefilePath               string
	AuthServers                []rainslib.ConnInfo
	PrivateKeyPath             string
	DoSharding                 bool
	KeepExistingShards         bool
	NofAssertionsPerShard      int
	MaxShardSize               int
	AddSignatureMetaData       bool
	AddSigMetaDataToAssertions bool
	AddSigMetaDataToShards     bool
	SignatureAlgorithm         rainslib.SignatureAlgorithmType
	KeyPhase                   int
	SigValidSince              time.Duration
	SigValidUntil              time.Duration
	SigSigningInterval         time.Duration
	DoConsistencyCheck         bool
	SortShards                 bool
	SigNotExpired              bool
	CheckStringFields          bool
	DoSigning                  bool
	MaxZoneSize                int
	OutputPath                 string
	DoPublish                  bool
}
