package publisher

import (
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/section"
)

//Config lists configurations for publishing zone information, see zonepub flag description for
//detail.
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

//ShardingConfig contains configuration options on how to split a zone into shards.
type ShardingConfig struct {
	DoSharding            bool
	KeepExistingShards    bool
	NofAssertionsPerShard int
	MaxShardSize          int
}

//PShardingConfig contains configuration options on how to split a zone into probabilistic shards.
type PShardingConfig struct {
	DoPsharding            bool
	KeepExistingPshards    bool
	NofAssertionsPerPshard int
	BloomFilterConf        BloomFilterConfig
}

//BloomFilterConfig specifies the bloom filter's meta data
type BloomFilterConfig struct {
	Hashfamily       []algorithmTypes.Hash
	NofHashFunctions int
	BFOpMode         section.ModeOfOperationType
	BloomFilterSize  int
}

//MetaDataConfig determines how the signature meta data is generated and to which section(s) it is
//added.
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

//ConsistencyConfig determines which consistency checks are performed prior to signing.
type ConsistencyConfig struct {
	DoConsistencyCheck bool
	SortShards         bool
	SigNotExpired      bool
	CheckStringFields  bool
}
