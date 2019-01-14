# RAINS server design

This document describes the implementation design of a RAINS servers and how it processes Queries
and Assertions depending on its configuration. A RAINS server consists of four modules which process
Queries and Assertions sequentially, a resolver which performs recursive lookups, six caches which
allow quick access to stored information, and three queues where incoming messages are places in
case of congestion.

## Modules

### Switchboard

The switchboard is responsible for handling all network connections. It is capable to listen on all
supported transport protocols and send RAINS messages on top of them. Currently, the switchboard
supports TLS-over-TCP, scion-UDP, and go channels as a transport. 

The switchboard acts on the following event as follows:
- Connection request from another server/client: If the source of the request is not blacklisted,
  the connection is accepted and a new go routine is created which listens for incoming messages.
- Incoming message on a connection: The cbor encoded message is decoded into a message object and
  passed to the inbox module.
- Send request to a network addr: If there is not an active connection with the destination, a new
  connection is opened. Then the message is cbor encoded and sent to the destination. If an error
  occurs, it retries the send the message for the specified amount of times. 
- Request for a recursive lookup: The message is forwarded to the configured recursive resolver.

### Inbox

The inbox is responsible for handling capabilities, prioritizing messages, and queuing the incoming
messages or assigning them to workers. 

The inbox first processes capabilities and takes appropriate actions. It then splits the messages
content into three groups - Notifications, Queries, and Assertions - which are handled separately.
Assertions which are an answer to a delegation query issued by this server are handled with
priority. All three groups are put onto dedicated queues from which the worker go routines start
processing the different parts of the incoming messages. 

All queries of a message are processed together. Also all Assertions of a message are processed
together. If a client wants several queries to be processed separately, he must send each query in a
separate message.

A worker go routine first checks the validity of the queries or assertions (implemented in the
Verify module) and if all of them are valid handles them in the query or assertion engine
(implemented in the Engine module). It then retrieves new queries or assertions from the queue and
restarts this process. 

### Verify

The Verify module checks Queries and Assertions for their validity. 

If any of the queries that are processed together has an invalid context, all of them are dropped
and a notification message is sent back to the sender. Expired queries are ignored. All remaining
queries are forwarded to the query engine.

Assertions are handled differently depending on the type of the server - authoritative or caching
resolver. Assertions sent not as a response to a query issued by the authoritative server are
dropped by the authoritative server if the server has not authority over that name. Otherwise, all
signatures on all assertions are checked. If any of the unexpired signatures is invalid or any
context is invalid or any contained assertions' zone is invalid, all assertions are dropped and
processing stops. If a signature is expired it is removed. If there is at least one unexpired
signature per Assertion, processing continues by forwarding the assertions to the assertion engine. 

In case a public key is missing to verify any of the signatures on any of the Assertions contained
in a message, one new messages is generated containing queries for all missing keys. This message is
then sent back to the server from which the message with the missing keys originated except when the
message was received from the zonePublisher. In that case the message is forwarded to the configured
recursive resolver. In the mean time, the Assertions are added to the pending key cache such that
this go routine can work on a different message.

### Engine

The Engine module is divided into query engine and assertion engine. They are performing the
final processing of queries and assertions.

The query engine first checks if there is a cached Assertion answering the query. If there is a
cache hit in the assertion cache, the cached assertions are directly returned and processing stops.
Otherwise, a lookup in the negative Assertion cache is performed and on a cache hit, the shard or
zone is returned and processing stops. In case of two cache misses, the queries are duplicated. One
of them is added to the pending query cache, while the other's Tocken is changed and forwarded to
the configured recursive resolver.

The assertion engine first checks if all Assertions are consistent. If not, all Assertion of the
same zone are removed from the cache and processing stops. Otherwise, it decides if an Assertion
will be cached and if so adds it to the assertion, negative assertion and/or zone key cache. It then
checks if the message that contained these Assertions was sent in response to a delegation query. If
so, the Assertions waiting for these public keys are loaded from the pending key cache and put on
the normal queue in the inbox module. The assertion engine then checks if the message that contained
these Assertions was sent as the final answer to a recursive lookup. If so, the servers from which
these queries originated are loaded from the pending query cache and the message is sent back
to all of these servers.

## Libresolve

This package implements a stub resolver for a client. It can either be a forwarder or a recursive
resolver.

### Forwarder

The forwarder simple forwards the received queries to all specified forwarders

### Recursive Resolver

The recursive resolver performs recursive lookups for a client or a server. It supports two modes,
blocking and non-blocking. In the non-blocking mode a network address must be specified where the
answer will be sent to. The recursive resolver caches delegation Assertions and keeps connection
open as an optimization. Delegation queries are answered directly from the delegation cache if
possible. Otherwise, and for all non-delegation queries a recursive lookup is started.

In a recursive lookup, the queries are forwarded to one of the configured root servers. When an
answer is received, the resolver checks if the response directly answers the query. In this case,
the response is returned. Otherwise, it checks if the response is a valid redirect. If so, the
queries are forwarded to the last server specified in the chain of redirects (in most cases there is
just one redirect). Otherwise, the answer is unrelated to the query and the resolver restarts the
recursive lookup at a different root server. If it does not get a valid response starting at any of
the configured root servers, processing stops and an error is returned.

## Caches

A RAINS server stores relevant information in the following caches. This subsection describes how
this caches are currently implemented. A description of the information they must provide is given
in the interface description (package cache, interfaces.go). All caches must be safe for concurrent
usage.

### Assertion Cache

The assertion cache can hold a configurable amount of assertions. When this limit is reached, the
least recently used assertion will be evicted from the cache. Assertions over which a server has
authority are exempt from this procedure and are only evicted once they have expired.

### Zone Key Cache

The zone key cache can hold a configurable amount of delegation assertions. When this limit is
reached, the least recently used delegation assertion will be evicted from the cache. After the
number of entries in the cache exceeds a configurable amount a warning is logged for each newly
added entry. A warning is logged as well when the amount of delegation assertions for a zone exceeds
a configurable amount.

### Negative Assertion Cache

The negative assertion cache can hold a configurable amount of shards and zones (Maybe change this
to the total size of the shards/zones instead of amount as their size can vary greatly!). When this
limit is reached, the least recently used shard or zone will be evicted from the cache. Shards and
zones over which a server has authority are exempt from this procedure and are only evicted once
they have expired.

### Connection

The connection cache can hold a configurable amount of connections. When this limit is reached, the
connections of the least recently used network address will be evicted from the cache. The server
can add to each cached network address which capabilities it supports. Note that capabilities are
stored per network address and not per connection.

### Capability Cache

The capability cache stores a mapping from a capability list hash to the capability list. This cache
is not bounded in the current implementation.

### Pending Query Cache

The pending query cache can hold a configurable amount of messages. When this limit is reached, an
error is logged and each newly added message will be dropped until an entry is removed from the
cache.

### Pending Key Cache

The pending key cache can hold a configurable amount of messages. When this limit is reached, an
error is logged and each newly added message will be dropped until an entry is removed from the
cache.

## Queues 

A RAINS server has three different queues to temporarily store data during times of high congestion.
All received messages are placed into one of the three queues but are processed right away under
normal load.

### Normal Queue

The normal queue is the default queue.

### Priority Queue

The priority queue is intended for answers to delegation queries issued by this server. This allows
faster processing of delegation assertions and thus, reduces query response time.

### Notification Queue

The notification queue is intended for messages containing information about the RAINS protocol
itself and is handled separate from the query and assertions processing path.

## Authoritative Server vs. Caching Resolver

An authoritative server caches all information about one or several zones. It is responsible to
reliably share its zone's/zones' information with the rest of the world. An authoritative server is
maintained by the authority over one or several zones. An authoritative server only answers queries
about a zone it has authority over with an Assertion and queries about a delegated subzone with glue
records (delegation, redirection, service, and ip4/ip6/scionAddr).

A caching resolver is a RAINS server which handles queries on behalf of several clients. By caching
answers to queries, it reduces query response time for subsequent queries about the same name/zone
and type. It may also proactively fetch the top n assertions shortly before they expire to improve
query response time.