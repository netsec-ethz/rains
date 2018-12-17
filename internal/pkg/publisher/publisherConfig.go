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
	IncludeShards         bool
	DoSharding            bool
	NofAssertionsPerShard int
	MaxShardSize          int
}

//PShardingConfig contains configuration options on how to split a zone into probabilistic shards.
type PShardingConfig struct {
	IncludePshards         bool
	DoPsharding            bool
	NofAssertionsPerPshard int
	BloomFilterConf        BloomFilterConfig
}

//BloomFilterConfig specifies the bloom filter's meta data
type BloomFilterConfig struct {
	BFAlgo          section.BloomFilterAlgo
	BFHash          algorithmTypes.Hash
	BloomFilterSize int
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
	SortZone           bool
	SigNotExpired      bool
	CheckStringFields  bool
}
