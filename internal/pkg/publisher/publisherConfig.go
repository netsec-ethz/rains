package publisher

import (
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/section"
)

// Config lists configurations for publishing zone information, see zonepub flag description for
// detail.
type Config struct {
	ZonefilePath    string
	AuthServers     []connection.Info
	PrivateKeyPath  string
	ShardingConf    ShardingConfig
	PShardingConf   PShardingConfig
	MetaDataConf    MetaDataConfig
	ConsistencyConf ConsistencyConfig
	DoSigning       bool
	MaxZoneSize     int
	OutputPath      string
	DoPublish       bool
}

// ShardingConfig contains configuration options on how to split a zone into shards.
type ShardingConfig struct {
	KeepShards            bool
	DoSharding            bool
	NofAssertionsPerShard int
	MaxShardSize          int
}

// PShardingConfig contains configuration options on how to split a zone into probabilistic shards.
type PShardingConfig struct {
	KeepPshards            bool
	DoPsharding            bool
	NofAssertionsPerPshard int
	BloomFilterConf        BloomFilterConfig
}

// BloomFilterConfig specifies the bloom filter's meta data
type BloomFilterConfig struct {
	BFAlgo          section.BloomFilterAlgo
	BFHash          algorithmTypes.Hash
	BloomFilterSize int
}

// MetaDataConfig determines how the signature meta data is generated and to which section(s) it is
// added.
type MetaDataConfig struct {
	AddSignatureMetaData       bool
	AddSigMetaDataToAssertions bool
	AddSigMetaDataToShards     bool
	AddSigMetaDataToPshards    bool
	SignatureAlgorithm         algorithmTypes.Signature
	KeyPhase                   int
	SigValidSince              int64
	SigValidUntil              int64
	SigSigningInterval         time.Duration
}

// ConsistencyConfig determines which consistency checks are performed prior to signing.
type ConsistencyConfig struct {
	DoConsistencyCheck bool
	SortShards         bool
	SortZone           bool
	SigNotExpired      bool
	CheckStringFields  bool
}

// DefaultConfig return the default configuration for the zone publisher.
func DefaultConfig() Config {
	return Config{
		ZonefilePath:   "data/zonefiles/zf.txt",
		AuthServers:    []connection.Info{},
		PrivateKeyPath: "data/keys/key_sec.pem",
		ShardingConf: ShardingConfig{
			DoSharding:            true,
			KeepShards:            false,
			MaxShardSize:          1000,
			NofAssertionsPerShard: -1,
		},
		PShardingConf: PShardingConfig{
			DoPsharding:            true,
			KeepPshards:            false,
			NofAssertionsPerPshard: 50,
			BloomFilterConf: BloomFilterConfig{
				BFAlgo:          section.BloomKM12,
				BFHash:          algorithmTypes.Shake256,
				BloomFilterSize: 200,
			},
		},
		MetaDataConf: MetaDataConfig{
			AddSignatureMetaData:       true,
			AddSigMetaDataToAssertions: true,
			AddSigMetaDataToShards:     true,
			AddSigMetaDataToPshards:    true,
			SignatureAlgorithm:         algorithmTypes.Ed25519,
			KeyPhase:                   0,
			SigValidSince:              time.Now().Unix(),
			SigValidUntil:              time.Now().Add(24 * time.Hour).Unix(),
			SigSigningInterval:         time.Minute,
		},
		ConsistencyConf: ConsistencyConfig{
			DoConsistencyCheck: true,
			SortShards:         false,
			SortZone:           false,
			SigNotExpired:      false,
			CheckStringFields:  false,
		},
		DoSigning:   true,
		MaxZoneSize: 60000,
		OutputPath:  "",
		DoPublish:   true,
	}
}
