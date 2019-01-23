zonepub(1) -- A RAINS publishing tool
===========================

## SYNOPSIS

`zonepub` [path] [options]

## DESCRIPTION

zonepub (short for zone publisher) is a tool for pushing sections to RAINS
servers from the command line. It reads a zone file and sends it to all
authoritative RAINS servers specified in the config file. If no path to a
config file is provided, the default config is used.

## OPTIONS

The following options can be specified in the configuration file for the rzpub
program. Keys are to be specified in a top-level JSON map.

* `--addSigMetaDataToAssertions`: this option only has an effect when AddSignatureMetaData is true.
   If set to true, signature meta data is added to all assertions contained in a shard or zone.
   (default true)
* `--addSigMetaDataToPshards`: this option only has an effect when AddSignatureMetaData is true. If
   set to true, signature meta data is added to all pshards contained the zone. (default true) 
* `--addSigMetaDataToShards`: this option only has an effect when AddSignatureMetaData is true. If
   set to true, signature meta data is added to all shards contained the zone. (default true) 
* `--addSignatureMetaData`: If set to true, adds signature meta data to sections (default true) 
* `--authServers`: Authoritative server addresses to which the sections in the
   zone file are forwarded. (default []) 
* `--bfAlgo`: Bloom filter's algorithm. (default bloomKM12)
* `--bfHash`: Hash algorithm used to add to or check bloomfilter. (default shake256)
* `--bloomFilterSize int`: Number of bytes in the bloom filter. (default 200) 
* `--checkStringFields`: If set to true, checks that none of the assertions' text fields contain
   protocol keywords. 
* `--doConsistencyCheck`: Performs all consistency checks if set to true. The check involves:
   sorting shards, sorting zones, checking that no signature is expired, and that all string
   fields contain no protocol keywords. (default true) 
* `--doPsharding`: If set to true, all assertions in the zonefile are grouped into pshards based on
   keepPshards, nofAssertionsPerPshard, bFAlgo, BFHash,and bloomFilterSize parameters. (default
   true) 
* `--doPublish`: If set to true, sends the signed sections to all authoritative rains servers. If
   the zone is smaller than the maximum allowed size, the zone is sent. Otherwise, the zone
   section's content is sent separately such that the maximum message size is not exceeded.
   (default true)
* `--doSharding`: If set to true, all assertions in the zonefile are grouped into pshards based on
   keepPshards, nofAssertionsPerPshard, bFAlgo, BFHash,and bloomFilterSize parameters. (default
   true) 
* `--doSigning`: If set to true, all sections with signature meta data are signed. (default true) 
* `--keepPshards`: this option only has an effect when DoPsharding is true. If the zonefile already
   contains pshards, they are kept. Otherwise, all existing pshards are removed before the new
   ones are created. 
* `--keepShards`: this option only has an effect when DoSharding is true. If the zonefile already
   contains shards, they are kept. Otherwise, all existing shards are removed before the new ones
   are created. 
* `--keyPhase`: int this option only has an effect when addSignatureMetaData is true. Defines the
   key phase in which the sections will be signed. Together with KeyPhase this uniquely defines
   which private key will be used. (default 0) 
* `--maxShardSize`: int this option only has an effect when DoSharding is true. Assertions are added
   to a shard until its size would become larger than maxShardSize in bytes. Then the process is
   repeated with a new shard. (default 1000)
* `--maxZoneSize`: int this option only has an effect when doSigning is true. If the zone's size is
   larger than maxZoneSize then only the zone's content is signed but not the zone itself.
   (default 60000) 
* `--nofAssertionsPerPshard`: int this option only has an effectwhen doPsharding is true. Defines
   the number of assertions with different names per pshard. (default 50) 
* `--nofAssertionsPerShard`: int this option only has an effect when DoSharding is true. Defines the
   number of assertions per shard (default -1) 
* `--outputPath`: string If not an empty string, a zonefile with the signed sections is generated
   and stored at the provided path. (default "") 
* `--privateKeyPath`: string Path to a file storing the private keys. Each line contains a key phase
   as integer and a private key encoded in hexadecimal separated by a space. (default
   "data/keys/key_sec.pem") 
* `--sigNotExpired`: If set to true, checks that all signatures have a validUntil time in the future
* `--sigSigningInterval`: int this option only has an effect when addSignatureMetaData is true.
   Defines the time interval in seconds over which the assertions' signature lifetimes are
   uniformly spread out. (default 1 minute) 
* `--sigValidSince`: int this option only has an effect when addSignatureMetaData is true. Defines
   the starting point of the SigSigningInterval for the Signature validSince values. Assertions'
   validSince values are uniformly spread out over this interval. Value must be an int64
   representing unix seconds since 1.1.1970. (default current time) 
* `--sigValidUntil`: int this option only has an effect when addSignatureMetaData is true. Defines
   the starting point of the SigSigningInterval for the Signature validUntil values. Assertions'
   validUntil values are uniformly spread out over this interval. Value must be an int64
   representing unix seconds since 1.1.1970 (default current time plus 24 hours) (default -1) 
* `--signatureAlgorithm`: this option only has an effect when addSignatureMetaData is true. Defines
   which algorithm will be used for signing. Together with keyPhase this uniquely defines which
   private key will be used. (default ed25519) 
* `--sortShards`: If set to true, makes sure that the assertions withing the shard are sorted. 
* `--sortZone`: If set to true, makes sure that the assertions withing the zone are sorted. 
* `--zonefilePath`: string Path to the zonefile (default "data/zonefiles/zf.txt")
