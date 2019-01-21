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

A capability represents a set of features the server supports, and is used for
advertising functionality to other servers. Currently only the following
capabilities are supported:

* `urn:x-rains:tlssrv` 

## OPTIONS

The following options can be specified in the configuration file for the rainsd
program. Keys are to be specified in a top-level JSON map.

* `RootZonePublicKeyPath`: Path to the file storing the RAINS' root zone public key.
* `AssertionCheckPointInterval`: The time duration in seconds after which a checkpoint of the
  assertion cache is performed.
* `NegAssertionCheckPointInterval`: The time duration in seconds after which a checkpoint of the
  negative assertion cache is performed.
* `ZoneKeyCheckPointInterval`: The time duration in seconds after which a checkpoint of the
  zone key cache is performed.
* `CheckPointPath`: Path where the server's checkpoint information is stored.
* `PreLoadCaches`: If true, the assertion, negative assertion, and zone key cache are pre-loaded
  from the checkpoint files in CheckPointPath at start up.
  
* `ServerAddress`: The network address of this server.
* `MaxConnections`: The maximum number of allowed active connections.
* `KeepAlivePeriod`: How long to keep idle connections open for,
* `TCPTimeout`: TCPTimeout is the maximum amount of time a dial will wait for a tcp connect to complete.
* `TLSCertificateFile`: The path to the server's tls certificate file proving the server's identity.
* `TLSPrivateKeyFile`: The path to the server's tls private key file proving the server's identity.

* `PrioBufferSize`: The maximum number of messages in the priority buffer,
* `NormalBufferSize`: The maximum number of messages in the normal buffer,
* `NotificationBufferSize`: The maximum number of messages in the notification buffer,
* `PrioWorkerCount`: Number of workers on the priority queue,
* `NormalWorkerCount`: Number of workers on the normal queue,
* `NotificationWorkerCount`: Number of workers on the notification queue,
* `CapabilitiesCacheSize`: Maximum number of elements in the capabilities cache,
* `Capabilities`: A list of capabilities this server supports.

* `ZoneKeyCacheSize`: The maximum number of entries in the zone key cache.
* `ZoneKeyCacheWarnSize`: When the number of elements in the zone key cache exceeds this value, a
  warning is logged.
* `MaxPublicKeysPerZone`: The maximum number of public keys for each zone.
* `PendingKeyCacheSize`: The maximum number of entries in the pending key cache.
* `DelegationQueryValidity`: The amount of seconds in the future when delegation queries are set to expire.
* `ReapVerifyTimeout`: The time interval to wait between removing expired entries from the various caches.

* `AssertionCacheSize`: The maximum number of entries in the assertion cache.
* `NegativeAssertionCacheSize`: The maximum number of entries in the negative assertion cache.
* `PendingQueryCacheSize`: The maximum number of entries in the pending query cache.
* `QueryValidity`: The amount of seconds in the future when a query is set to expire.
//TODO take the following to entries into one struct so context and zone are bound together.
* `ContextAuthority`: The context within which this server is authoritative,
* `ZoneAuthority`: The zones for which this server is authoritative,
* `MaxCacheValidity`: contains for each cache the maximum number of seconds an entry can be in the
  cache before it expires. It is not guaranteed that expired entries are directly removed.
  //TODO make a reap time for each server separately.
* `ReapEngineTimeout`: Timeout for cache reaping routines in the server,
