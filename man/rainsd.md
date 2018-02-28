rainsd(8) -- A RAINS server
===========================

## DESCRIPTION

This program implements a RAINS server which serves requests over the RAINS
protocol. The server can be configured to support any and all of the following
modes of operation:

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

* `RootZonePublicKeyPath`: Path to the public key of the root RAINS zone,
* `ServerAddress`: List of addresses to proxy requests to,
* `MaxConnections`: The maximum number of connections to open,
* `KeepAlivePeriod`: How long to keep idle connections open for,
* `TCPTimeout`: How long to wait when reading / writing from a connection
    before throwing an error,
* `TLSPublicKeyFile`: The public key for the server identity,
* `TLSPrivateKeyFile`: The provate key fro the server identity,

* `MaxMsgByteLength`: The maximum permitted message length to send. Sending
    will fail if the length exceeds this value,
* `PrioBufferSize`: The number of messages in the priority buffer,
* `NormalBufferSize`: The number of messages in the normal buffer,
* `NotificationBufferSize`: The number of messages in the notification buffer,
* `PrioWorkerCount`: Number of workers for priority messages,
* `NormalWorkerCount`: Number of workers for normal messages,
* `NotificationWorkerCount`: Number of workers for notification messages,
* `CapabilitiesCacheSize`: Number of capabilities to hold in cache,
* `PeerToCapCacheSize`: UNUSED
* `ActiveTokenCacheSize`: UNUSED
* `Capabilities`: Which capabilities this server will advertise supporting,

* `ZoneKeyCacheSize`: The number of entries in the zone key cache, which is
    used to store the public keys of zones and their assertions,
* `ZoneKeyCacheWarnSize`: Print warnings when the cache exeeds this size,
* `MaxPublicKeysPerZone`: The maximum number of public keys for each zone,
* `PendingKeyCacheSize`: Size of the cache which contains all sections that are
    waiting for a delegation response in order to verify their signatures,
* `InfrastructureKeyCacheSize` UNUSED
* `ExternalKeyCacheSize` UNUSED
* `DelegationQueryValidity`: The maximum validity period for which a delegation
    is considered valid,
* `ReapVerifyTimeout`: The time interval to wait between reaping unwanted
    entries from the various caches,

* `AssertionCacheSize`: The maximum number of assertions to keep in cache at
    any point in time,
* `NegativeAssertionCacheSize`: The maximum number of negative assertions to
    keep in cache at any point in time,
* `PendingQueryCacheSize`: Cache mapping all self-issued pending pqueries to
    the set of messages waiting for that response,
* `RedirectionCacheSize`: Cache for fast retrieval of connection information
    for a given subject zone,
* `RedirectionCacheWarnSize`:
* `QueryValidity`
* `AddressQueryValidity`
* `ContextAuthority`: The context within which this server is authoritative,
* `ZoneAuthority`: The zones for which this server is authoritative,
* `MaxCacheValidity`: a map containing validity entries for the caches in the
    server,
* `ReapEngineTimeout`
