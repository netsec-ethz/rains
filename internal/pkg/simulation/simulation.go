package simulation

type Config struct {
	Paths        Paths
	RootZone     Zone
	TLDZones     Zone
	HybridZones  Zone
	Zipfs        Zipfs
	NofSLDs      int
	IsLeafZone   int //probability that the zone is a leaf zone. Otherwise it is a hybrid zone. Value between 0 (never) and 100 (always)
	RootIPAddr   string
	NofResolvers int
	NofClients   int

	/*NofRootNamingServers      int
	NofTLDNamingServers       int
	NofSLDNamingServersPerTLD int
	LeafZoneSize              int*/
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
			S:    2,
			Seed: 0,
		},
		LeafZoneSize: ZipfParams{
			Size: 15,
			S:    4,
			Seed: 0,
		},
	},
	NofSLDs:      1,
	IsLeafZone:   100,
	RootIPAddr:   "0.0.0.0",
	NofResolvers: 1,
	NofClients:   1,
}
