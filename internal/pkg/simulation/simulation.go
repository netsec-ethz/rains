package simulation

import (
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
)

type Message struct {
	Info     message.Message
	SendTime int64 //Nanoseconds since 1.1.1970
}

type Queries struct {
	Trace []Message
	Dst   string //resolver's identifier
	ID    string //client ID
}

type NameType struct {
	Name string
	Type object.Type
}

type NameIPAddr struct {
	Name   string
	IPAddr string
}

type ClientInfo struct {
	Resolver string
	TLD      int
}

type Config struct {
	Paths                Paths
	RootZone             Zone
	TLDZones             Zone
	HybridZones          Zone
	Zipfs                Zipfs
	NofSLDs              int
	IsLeafZone           int //probability that the zone is a leaf zone. Otherwise it is a hybrid zone. Value between 0 (never) and 100 (always)
	RootIPAddr           string
	ClientsPerTLDName    int //is the number of clients a TLD/country has per name
	MaxQueriesPerClient  int
	FractionNegQuery     int
	FractionLocalQueries int   //probability that the query is a local name. Value between 0 (never) and 100 (always)
	Start                int64 //Start time of the experiment in nanoseconds since 1.1.1970
	End                  int64 //End time of the experiment in nanoseconds since 1.1.1970
	ClientResolverDelay  time.Duration
	StartPort            int
}

type Paths struct {
	ZonefilePath               string
	CertificatePath            string
	ConfigsPath                string
	KeysPath                   string
	RootDelegAssertionFilePath string
	PrivateKeyFileNamePrefix   string
}

type Zone struct {
	Name                   string
	Size                   int
	MaxShardSize           int
	NofAssertionsPerPshard float64
	ProbabilityBound       float64
}

type Zipfs struct {
	Root         ZipfParams
	LeafZoneSize ZipfParams
	TLDContinent ZipfParams
	GlobalQuery  ZipfParams
	LocalQuery   ZipfParams
}

type ZipfParams struct {
	Size uint64
	S    float64
	V    float64
	Seed int64
}

var Example = Config{
	Paths: Paths{
		CertificatePath:            "cert/",
		ConfigsPath:                "conf/",
		KeysPath:                   "keys/",
		ZonefilePath:               "zonefiles/",
		RootDelegAssertionFilePath: "keys/selfSignedRootDelegationAssertion.gob",
		PrivateKeyFileNamePrefix:   "privateKey",
	},
	RootZone: Zone{
		Name:                   "Root",
		Size:                   1,
		MaxShardSize:           500,
		NofAssertionsPerPshard: 10,
		ProbabilityBound:       10000000,
	},
	TLDZones: Zone{
		MaxShardSize:           500,
		NofAssertionsPerPshard: 10,
		ProbabilityBound:       10000000,
	},
	HybridZones: Zone{
		MaxShardSize:           500,
		NofAssertionsPerPshard: 10,
		ProbabilityBound:       10000000,
	},
	Zipfs: Zipfs{
		Root: ZipfParams{
			S:    1.1,
			Seed: 0,
		},
		LeafZoneSize: ZipfParams{
			Size: 15,
			S:    3,
			Seed: 0,
		},
		TLDContinent: ZipfParams{
			Size: 5,
			S:    1.01,
			Seed: 0,
		},
		GlobalQuery: ZipfParams{
			S:    1.01,
			Seed: 0,
		},
		LocalQuery: ZipfParams{
			S:    1.01,
			Seed: 0,
		},
	},
	NofSLDs:              1,
	IsLeafZone:           100,
	RootIPAddr:           "0.0.0.0",
	ClientsPerTLDName:    10000,
	MaxQueriesPerClient:  100,
	FractionNegQuery:     3,
	FractionLocalQueries: 80,
	Start:                time.Now().Add(time.Second).UnixNano(),
	End:                  time.Now().Add(5 * time.Second).UnixNano(),
	ClientResolverDelay:  time.Millisecond,
	StartPort:            5022,
}
