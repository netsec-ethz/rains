rzpub(1) -- A RAINS publishing tool
===========================

## DESCRIPTION

rzpub (short for RAINS zone publisher) is a tool for pushing sections to RAINS
servers from the command line. It reads a zone file and sends it to all
authoritative RAINS servers specified in the config file. The default location
of the config file is at [TODO add location] and of the zone file at [TODO add
location] if not told otherwise by a command line flag.

## OPTIONS

The following options can be specified in the configuration file for the rzpub
program. Keys are to be specified in a top-level JSON map.

* `ZonefilePath`: Path to the zonefile. The zonefile must contain exactly one zoneBody as the top
  most element according to the zonefile format.
* `ConfigPath`: Path to the config file
* `AuthServers`: Authoritative server addresses to which the sections in the zone file are forwarded
* `PrivateKeyPath`: Path to a file storing the private keys. Each line contains a key phase and a
  private key encoded in hexadecimal separated by a space.
* `DoSharding`: If set to true, all assertions in the zonefile are grouped into shards based on
  KeepExistingShards and, NofAssertionsPerShard or MaxShardSize parameters. If NofAssertionsPerShard
  and MaxShardSize are set, the latter takes precedence.
* `KeepExistingShards`: this option only has an effect when DoSharding is true. If the zonefile
  already contains shards and keepExistingShards is true, the shards are kept. Otherwise, all
  existing shards are removed before the new ones are created.
* `NofAssertionsPerShard`: this option only has an effect when doSharding is true. Defines the
  number of assertions per shard if sharding is performed
* `MaxShardSize`: this option only has an effect when DoSharding is true. Assertions are added to a
  shard until its size would become larger than maxShardSize. Then the process is repeated with a
  new shard.
* `AddSignatureMetaData`: If set to true, signature meta data are added to sections according to
  other configuration parameters
* `AddSigMetaDataToAssertions`: this option only has an effect when AddSignatureMetaData is true. If
  set to true, signature meta data is added to all assertions contained in a shard or zone.
* `AddSigMetaDataToShards`: this option only has an effect when AddSignatureMetaData is true. If set
  to true, signature meta data is added to all shards contained the zone.
* `SignatureAlgorithm`: this option only has an effect when AddSignatureMetaData is true. Defines
  which algorithm will be used for signing. Together with KeyPhase this uniquely defines which
  private key will be used.
* `KeyPhase`: this option only has an effect when AddSignatureMetaData is true. Defines the key
  phase in which the sections will be signed. Together with KeyPhase this uniquely defines which
  private key will be used.
* `SigValidSince`: this option only has an effect when AddSignatureMetaData is true. Defines the
  starting point of the SigSigningInterval for the Signature validSince values. Assertions'
  validSince values are uniformly spread out over this interval. Value must be an int64 representing
  unix seconds since 1.1.1970.
* `SigValidUntil`: this option only has an effect when AddSignatureMetaData is true. Defines the
  starting point of the SigSigningInterval for the Signature validUntil values. Assertions'
  validUntil values are uniformly spread out over this interval. Value must be an int64 representing
  unix seconds since 1.1.1970.
* `SigSigningInterval`: this option only has an effect when AddSignatureMetaData is true. Defines
  the time interval in seconds over which the assertions' signature lifetimes are uniformly spread
  out.
* `DoConsistencyCheck`: if set to true, all consistency checks are performed before signing. The
  check involves: TODO CFE
* `SortShards`: If set to true, makes sure that all assertions withing the shard are sorted before
  signing.
* `SigNotExpired`: If set to true, checks that all signatures have a validUntil time in the future
  before signing.
* `CheckStringFields`: If set to true, checks that none of the assertions' text fields contain
  type markers which are part of the protocol syntax (TODO CFE use more precise
  vocabulary)
* `DoSigning`: If set to true, all sections with signature meta data are signed.
* `MaxZoneSize`: this option only has an effect when DoSigning is true. If the zone's size is larger
  than MaxZoneSize then only the zone's content is signed but not the zone itself.
* `OutputPath`: If not an empty string, a zonefile with the signed sections is generated and
  stored at the provided path
* `DoPublish`: If set to true, sends the signed sections to all authoritative rains servers. If the
  zone is smaller than the maximum allowed size, the zone is sent. Otherwise, the zone section's
  content is sent separately such that the maximum message size is not exceeded.