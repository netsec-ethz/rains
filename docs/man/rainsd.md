rainsd(8) -- A RAINS server
===========================

## SYNOPSIS

`rainsd` [path] [options]

## DESCRIPTION

This program implements a RAINS server which serves requests over the RAINS protocol. 
The server can be configured to support the first two modes of operation. The third one
is not yet implemented.

* authority service -- the server acts on behalf of an authority to ensure
 properly signed assertions are available to the system,
* query service -- the server acts on behalf of clients to respond to queries
 with relevant assertions to answer these queries,
* intermediary service -- the server provides storage and lookup services to
 authority services and query services.

If no path to a config file is provided, the default config is used.

A capability represents a set of features the server supports, and is used for
advertising functionality to other servers. Currently only the following
capabilities are supported:

* `urn:x-rains:tlssrv` 

## OPTIONS

The following options can be specified in the configuration file for the rainsd
program. Keys are to be specified in a top-level JSON map.

* `--assertionCacheSize`: int The maximum number of entries in the assertion cache. (default 10000)
* `--assertionCheckPointInterval`: duration The time duration in seconds after which a checkpoint of
  the assertion cache is performed. (default 30m0s)
* `--authorities`: main.authoritiesFlag A list of contexts and zones for which this server is
  authoritative. The format is elem(,elem) where elem := zoneName,contextName (default [])
* `--capabilities`: string A list of capabilities this server supports. (default
  "urn:x-rains:tlssrv")
* `--capabilitiesCacheSize`: int Maximum number of elements in the capabilities cache. (default 10)
* `--checkPointPath`: string Path where the server's checkpoint information is stored. (default
  "data/checkpoint/resolver/")
* `--delegationQueryValidity`: duration The amount of seconds in the future when delegation queries
  are set to expire. (default 1s)
* `--dispatcherSock`: string TODO write description
* `--keepAlivePeriod`: duration How long to keep idle connections open. (default 1m0s)
* `--maxAssertionValidity`: duration contains the maximum number of seconds an assertion can be in
  the cache before the cached entry expires. It is not guaranteed that expired entries are directly
  removed. (default 3h0m0s)
* `--maxConnections`: int The maximum number of allowed active connections. (default 10000)
* `--maxPshardValidity`: duration contains the maximum number of seconds an pshard can be in the
  cache before the cached entry expires. It is not guaranteed that expired entries are directly
  removed. (default 3h0m0s)
* `--maxPublicKeysPerZone`: int The maximum number of public keys for each zone. (default 5)
* `--maxShardValidity`: duration contains the maximum number of seconds an shard can be in the cache
  before the cached entry expires. It is not guaranteed that expired entries are directly removed.
  (default 3h0m0s)
* `--maxZoneValidity`: duration contains the maximum number of seconds an zone can be in the cache
  before the cached entry expires. It is not guaranteed that expired entries are directly removed.
  (default 3h0m0s)
* `--negAssertionCheckPointInterval`: duration The time duration in seconds after which a checkpoint
  of the negative assertion cache is performed. (default 1h0m0s)
* `--negativeAssertionCacheSize`: int The maximum number of entries in the negative assertion cache.
  (default 1000)
* `--normalBufferSize`: int The maximum number of messages in the normal buffer. (default 100)
* `--normalWorkerCount`: int Number of workers on the normal queue. (default 10)
* `--notificationBufferSize`: int The maximum number of messages in the notification buffer.
  (default 10)
* `--notificationWorkerCount`: int Number of workers on the notification queue. (default 1)
* `--pendingKeyCacheSize`: intThe maximum number of entries in the pending key cache. (default 100)
* `--pendingQueryCacheSize`: int The maximum number of entries in the pending query cache. (default
  1000)
* `--preLoadCaches`: If true, the assertion, negative assertion, and zone key cache are pre-loaded
  from the checkpoint files in CheckPointPath at start up.
* `--prioBufferSize`: int The maximum number of messages in the priority buffer. (default 50)
* `--prioWorkerCount`: int Number of workers on the priority queue. (default 2)
* `--queryValidity`: duration The amount of seconds in the future when a query is set to expire.
  (default 1s)
* `--reapAssertionCacheInterval`: duration The time interval to wait between removing expired
  entries from the assertion cache. (default 15m0s)
* `--reapNegAssertionCacheInterval`: duration The time interval to wait between removing expired
  entries from the negative assertion cache. (default 15m0s)
* `--reapPendingKeyCacheInterval`: duration The time interval to wait between removing expired
  entries from the pending key cache. (default 15m0s)
* `--reapPendingQCacheInterval`: duration The time interval to wait between removing expired entries
  from the pending query cache. (default 15m0s)
* `--reapZoneKeyCacheInterval`: duration The time interval to wait between removing expired entries
  from the zone key cache. (default 15m0s)
* `--rootZonePublicKeyPath`: string Path to the file storing the RAINS' root zone public key.
  (default "data/keys/rootDelegationAssertion.gob")
* `--sciondSock`: string TODO write description
* `--serverAddress`: main.addressFlag The network address of this server. (default 127.0.0.1:55553)
* `--tcpTimeout`: duration TCPTimeout is the maximum amount of time a dial will wait for a tcp
  connect to complete. (default 5m0s)
* `--tlsCertificateFile`: string The path to the server's tls certificate file proving the server's
  identity. (default "data/cert/server.crt")
* `--tlsPrivateKeyFile`: string The path to the server's tls private key file proving the server's
  identity. (default "data/cert/server.key")
* `--zoneKeyCacheSize`: int The maximum number of entries in the zone key cache. (default 1000)
* `--zoneKeyCacheWarnSize`: int When the number of elements in the zone key cache exceeds this
  value, a warning is logged. (default 750)
* `--zoneKeyCheckPointInterval`: duration The time duration in seconds after which a checkpoint of
  the zone key cache is performed. (default 30m0s)