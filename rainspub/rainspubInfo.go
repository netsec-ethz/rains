package rainspub

import (
	"time"

	"github.com/netsec-ethz/rains/rainslib"
)

//parser is used to extract assertions from a rains zone file.
var parser rainslib.ZoneFileParser

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
	ZonefilePath          string
	PrivateKeyPath        string
	DoSharding            bool
	NofAssertionsPerShard int
	AddSignatureMetaData  bool
	SignatureAlgorithm    rainslib.SignatureAlgorithmType
	KeyPhase              int
	SigValidSince         time.Duration
	SigValidUntil         time.Duration
	SigSigningInterval    time.Duration
	DoConsistencyCheck    bool
	SortShards            bool
	SigNotExpired         bool
	CheckStringFields     bool
	DoSigning             bool
	SignAssertions        bool
	SignShards            bool
	OutputFilePath        bool
	DoPublish             bool
}
