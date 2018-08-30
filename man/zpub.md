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

* `ZonefilePath`: Path to the zonefile
* `ConfigPath`: Path to the config file
* `AuthServers`: Authoritative server addresses to which the sections in the
  zone file are forwarded
* `PrivateKeyPath`: Path to a file storing the private keys. Each line contains
  a key phase and a private key encoded in hexadecimal separated by a space.
* `doSharding`: If set to true, only assertions in the zonefile are considered
  and grouped into shards based on configuration
* `NofAssertionsPerShard`: Defines the number of assertions per shard if
  sharding is performed
* `AddSignatureMetaData`: If set to true, adds signature meta data to sections
* `SignatureAlgorithm`: Algorithm to be used for signing
* `KeyPhase`: Defines which private key is used for signing
* `SigValidSince`: Defines the starting point of the SigSigningInterval for the
  Signature validSince values. Assertions' validSince values are uniformly
  spread out over this interval. Value must be an int64 representing unix seconds since 1.1.1970.
* `SigValidUntil`: Defines the starting point of the SigSigningInterval for the
  Signature validUntil values. Assertions' validUntil values are uniformly
  spread out over this interval. Value must be an int64 representing unix seconds since 1.1.1970.
* `SigSigningInterval`: Defines the time interval in seconds over which the assertions'
  signature lifetimes are uniformly spread out.
* `DoConsistencyCheck`: Performs all consistency checks if set to true. The
  check involves: TODO CFE
* `SortShards`: If set, makes sure that the assertions withing the shard are sorted.
* `SigNotExpired`: If set, checks that all signatures have a validUntil time in the
  future
* `CheckStringFields`: If set, checks that none of the assertions' text fields contain
  type markers which are part of the protocol syntax (TODO CFE use more precise
  vocabulary)
* `DoSigning`: If set, signs all assertions and shards
* `SignAssertions`: If set, signs all assertions
* `SignShards`: If set, signs all shards
* `OutputFilePath`: If set, a zonefile with the signed sections is generated and
  stored at the provided path
* `DoPublish`: If set, sends the signed sections to all authoritative rainsd servers

## Issues

TODO how to handle/spread shards