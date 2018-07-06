package zonepub

import (
	"time"

	"github.com/netsec-ethz/rains/rainslib"
)

//config contains configurations for publishing a rains zone file
var config zonepubConfig

//parser is used to extract assertions from a rains zone file.
var parser rainslib.ZoneFileParser

//subordinateDelegations is a list of all subordinate zones and the delegation schedule with them.
var subordinateDelegations []delegationInfo

//keyPhaseToPath maps the keyphase to the path leading to the private key of this keyphase
var keyPhaseToPath map[int]string

//zonepubConfig lists configurations for publishing zone information
type zonepubConfig struct {
	//AssertionValidity defines the time when an assertion (except a delegation assertion) is valid
	//starting from the time it is signed
	AssertionValidSince time.Duration //in hours
	//DelegationValidity defines the time when a delegation assertion is valid starting from the
	//time it is signed
	DelegationValidSince time.Duration //in hours
	//ShardValidity defines the time when a shard is valid starting from the time it is signed
	ShardValidSince time.Duration //in hours
	//ZoneValidity defines the time when a zone is valid starting from the time it is signed
	ZoneValidSince time.Duration //in hours
	//AssertionValidity defines the time until an assertion (except a delegation assertion) is valid
	//starting from the time it is signed
	AssertionValidUntil time.Duration //in hours
	//DelegationValidity defines the time until a delegation assertion is valid starting from the
	//time it is signed
	DelegationValidUntil time.Duration //in hours
	//ShardValidity defines the time until a shard is valid starting from the time it is signed
	ShardValidUntil time.Duration //in hours
	//ZoneValidity defines the time until a zone is valid starting from the time it is signed
	ZoneValidUntil time.Duration //in hours
	//ServerAddresses of the rainsd servers to which rainspub is pushing zone file information
	ServerAddresses []rainslib.ConnInfo
	//ZoneFilePath is the location of the rains zone file
	ZoneFilePath string
	//ZonePrivateKeyPath is the location of the zone's privateKey
	ZonePrivateKeyPath []string
	//DelegationStart defines the time when the superordinate delegated to this zone.
	DelegationStart time.Time
	//DelegationInterval defines the time period after which the next delegation assertion to this
	//zone should be available.
	DelegationInterval time.Duration //in minutes
	//PublishInterval defines the time interval after which it republishes the zonefile.
	PublishInterval time.Duration //in seconds
	//NofKeyPhases defines the number of key phases
	NofKeyPhases int
}

//delegationInfo stores meta data about a delegation issuing schedule for this zone's subordinates.
type delegationInfo struct {
	Delegation rainslib.AssertionSection //Delegation information
	Start      time.Time                 //Start time of delegation to subordinate
	Interval   time.Duration             //Time period after which the next delegation will be issued
}
