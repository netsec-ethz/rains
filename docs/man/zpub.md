rzpub(1) -- A RAINS publishing tool
===========================

## SYNOPSIS

`rzpub` [path] [options]

## DESCRIPTION

rzpub (short for RAINS zone publisher) is a tool for pushing sections to RAINS
servers from the command line. It reads a zone file and sends it to all
authoritative RAINS servers specified in the config file. The default location
of the config file is at [TODO add location] and of the zone file at [TODO add
location] if not told otherwise by a command line flag.

## OPTIONS

The following options can be specified in the configuration file for the rzpub
program. Keys are to be specified in a top-level JSON map.

* path : Path to the config file
* `--zonefilePath`: Path to the zonefile. The zonefile must contain exactly one zoneBody as the top
  most element according to the zonefile format.
* `--authServers`: Authoritative server addresses to which the sections in the zone file are forwarded
* `--privateKeyPath`: Path to a file storing the private keys. Each line contains a key phase and a
  private key encoded in hexadecimal separated by a space.
* `--doSharding`: If set to true, all assertions in the zonefile are grouped into shards based on
  KeepExistingShards and, NofAssertionsPerShard or MaxShardSize parameters. If NofAssertionsPerShard
  and MaxShardSize are set, the latter takes precedence.
* `--keepShards`: this option only has an effect when DoSharding is true. If the zonefile
  already contains shards and keepExistingShards is true, the shards are kept. Otherwise, all
  existing shards are removed before the new ones are created.
* `--nofAssertionsPerShard`: this option only has an effect when doSharding is true. Defines the
  number of assertions with different names per shard if sharding is performed. Because the number
  of assertions per name can vary, shards may have different sizes.
* `--maxShardSize`: this option only has an effect when DoSharding is true. Assertions are added to a
  shard until its size would become larger than maxShardSize bytes. Then the process is repeated with a
  new shard.
* `--doPsharding` : If set to true, all assertions in the zonefile are grouped into pshards based on
  KeepExistingPshards, NofAssertionsPerPshard, Hashfamily, NofHashFunctions, BFOpMode, and
  BloomFilterSize parameters.
* `--keepPshards`: this option only has an effect when DoPsharding is true. If the zonefile
  already contains pshards and keepExistingPshards is true, the pshards are kept. Otherwise, all
  existing pshards are removed before the new ones are created.
* `--nofAssertionsPerPshard`: this option only has an effect when doPsharding is true. Defines the
  number of assertions with different names per pshard if sharding is performed. Because the number
  of assertions per name can vary, shards may have different sizes.
* `--hashfamily` : A list of hash algorithm identifiers present in the hash family.
* `--nofHashFunctions` : The number of hash functions used to add to and query the bloom filter.
* `--bFOpMode` : Bloom filter's mode of operation
* `--bloomFilterSize` : Number of bits in the bloom filter. It will be rounded up to the next multiple
  of eight.
* `--addSignatureMetaData`: If set to true, signature meta data are added to sections according to
  other configuration parameters
* `--addSigMetaDataToAssertions`: this option only has an effect when AddSignatureMetaData is true. If
  set to true, signature meta data is added to all assertions contained in a shard or zone.
* `--addSigMetaDataToShards`: this option only has an effect when AddSignatureMetaData is true. If set
  to true, signature meta data is added to all shards contained the zone.
* `--addSigMetaDataPshards`: this option only has an effect when AddSignatureMetaData is true. If set
  to true, signature meta data is added to all pshards contained the zone.
* `--signatureAlgorithm`: this option only has an effect when AddSignatureMetaData is true. Defines
  which algorithm will be used for signing. Together with KeyPhase this uniquely defines which
  private key will be used.
* `--keyPhase`: this option only has an effect when AddSignatureMetaData is true. Defines the key
  phase in which the sections will be signed. Together with KeyPhase this uniquely defines which
  private key will be used.
* `--sigValidSince`: this option only has an effect when AddSignatureMetaData is true. Defines the
  starting point of the SigSigningInterval for the Signature validSince values. Assertions'
  validSince values are uniformly spread out over this interval. Value must be an int64 representing
  unix seconds since 1.1.1970.
* `--sigValidUntil`: this option only has an effect when AddSignatureMetaData is true. Defines the
  starting point of the SigSigningInterval for the Signature validUntil values. Assertions'
  validUntil values are uniformly spread out over this interval. Value must be an int64 representing
  unix seconds since 1.1.1970.
* `--sigSigningInterval`: this option only has an effect when AddSignatureMetaData is true. Defines
  the time interval in seconds over which the assertions' signature lifetimes are uniformly spread
  out.
* `--doConsistencyCheck`: if set to true, all consistency checks are performed before signing. The
  check involves: TODO CFE
* `--sortShards`: If set to true, makes sure that all assertions withing the shard are sorted before
  signing.
* `--sigNotExpired`: If set to true, checks that all signatures have a validUntil time in the future
  before signing.
* `--checkStringFields`: If set to true, checks that none of the assertions' text fields contain
  type markers which are part of the protocol syntax (TODO CFE use more precise
  vocabulary)
* `--doSigning`: If set to true, all sections with signature meta data are signed.
* `--maxZoneSize`: this option only has an effect when DoSigning is true. If the zone's size is larger
  than MaxZoneSize then only the zone's content is signed but not the zone itself.
* `--outputPath`: If not an empty string, a zonefile with the signed sections is generated and
  stored at the provided path
* `--doPublish`: If set to true, sends the signed sections to all authoritative rains servers. If the
  zone is smaller than the maximum allowed size, the zone is sent. Otherwise, the zone section's
  content is sent separately such that the maximum message size is not exceeded.
