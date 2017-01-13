# RAINS, Another Internet Naming Services

This repository will contain a reference implementation of a RAINS server,
supporting authority, intermediary, and query service, as well as associated
tools for managing the server. It has the following entry points:

- `rainsd`:   A RAINS server
- `rainsdig`: A command-line RAINS client for query debugging
- `rainspub`: A command-line RAINS authority client for 
              publishing assertions to an authority service
- `rainsfic`: A tool for generating assertions to publish for
              publishing with `rainspub` for testing purposes.

In addition, the `rainslib` library on which the server and tools are built
provides common handling for the CBOR-based RAINS information model. There may
be a `rainsclientlib` as well for client-side name resolution; bonus points
for integrating this with the Go net package in an idiomatic way.

## rainsd architecture and design

The RAINS server itself is made up of several components:

- A server query engine (`engine.go`): This component stores the assertions
  the server knows about, the queries it doesn't yet have answers to.
- A verification engine (`verify.go`): This component stores delegations the server knows about, and uses these to verify signatures of 

- A message processor (`inbox.go`): This component processes incoming
  messages, demarshaling them, verifying their signatures, and handing them to
  the query engine for further processing.
- A switchboard (`switchboard.go`): The other components of rainsd operate in
  terms of messages associated with a RAINS server identity. The switchboard
  maintains open connections to other RAINS servers using a least-recently used
  cache, reopening connections that have timed out.

In addition, the RAINS server uses the following component provided by `rainslib`:

- A data model implementation (`model.go`): This component defines the core runtime data types,
  handles marshaling and unmarshaling of RAINS messages into and out of CBOR, the parsing and
  generation of RAINS zonefiles, and utilities for signing assertions and verifying signatures.

### query engine design {#engine}

The query engine is built around two tables: an *assertion cache*, a
*pending queries cache*..

The assertion cache stores assertions this instance knows about, indexed by
the fields in a query: context, zone, name, object type. Each entry has an
expiration time, derived from the last-expiring signature on an assertion, to
aid in reaping expired entries. The assertion cache should be able to return
both a value (for internal queries, i.e. when the RAINS server itself needs to
know another RAINS server's address to connect to it) as well as an assertion
(in order to answer queries from peers).

Assertions in the assertion cache are assumed to have valid signatures at the
time of insertion into the assertion cache; it is the responsibility of the
message processor to check for validity (and to handle errors for invalid
signatures).

Note that the assertion cache is a candidate for refactoring into `rainslib`
as it might be useful in the RAINS client implementation, as well.

The pending queries cache stores unexpired queries for which assertions are
not yet available. A query that cannot be immediately answered is placed into
the pending queries cache, and checked against incoming assertions until it
expires.

The query engine has a simple API, with three entry points:

- `assert(assertion)`: add an assertion to the assertion cache. Trigger any
   pending queries answered by it. The assertion's signatures are assumed to have
   already been verified through the verification engine. Validity times are
   taken from the signatures
- `assert(shard)`: add a shard full of assertions to the assertion cache. The
   shard's signature is assumed to have been already been verified through the
   verification engine. adds information about the shard to the range index. recursively asserts contained assertions.
- `assert(zone)`: add a zone full of assertions to the assertion cache. The
   shard's signature is assumed to have been already been verified through the
   verification engine. adds information about the zone 
- `query(query, callback)`: Run the specified callback when the query is
   answerable. Do so immediately on an assertion cache hit, or after an assertion
   is available
- `reap()`: remove expired queries and assertions. This is
   probably simply called by a goroutine waiting on a tick channel.

The design of the internal data structures for the query engine is separate
from that of the `rainslib` data model. The `rainslib` data model is optimized
to be close to the wire, and easy to marshal/unmarshal to and from CBOR. The
query engine structures are optimized for fast access given a key (name to
zone, name to contexts, context/zone/name/type(s) to assertions and/or
queries). The query engine structures point either to raw assertions or raw
queries in the `rainslib` data model, as "provenance" for a given question or answer. 

Care must be taken in this design to handle nonexistence proofs based on
shards efficiently. Suggestion: when asserting a shard, add it (as provenance)
to a range index, and consult this range on a cache miss. Zones should be
similarly stored (without range index), and returned as a last resort.

#### short assertions and short queries

There is a fair amount of complexity involved in marshaling and unmarshaling
CBOR as defined in the RAINS protocol draft (see [the datamodel](#datamodel)
for more details). Some of this complexity may be removed from the draft based
on experience with this prototype. Prototyping will therefore work on "short
assertions" and "short queries" instead.

An unsigned short assertion is a UTF-8 string of the form "A context zone
subject objtype value" where:

- context is the context of the assumption
- zone is the name of the subject zone
- subject is the subject name within the zone
- objtype is one of:
    - ip4 for an IPv4 address; value is parseable address in string form
    - ip6 for an IPv6 address; value is parseable address in string form
    - name for a name; value is name as string
    - deleg for a delegation; value is cipher number, space, delegation key as hex string
    - redir for a redirection; value is authority server name
    - infra for an infrastructure key; value is cipher number, space, key as hex string
    - cert for a certificate; not yet implemented
    - nameset for a nameset; not yet implemented
    - regr for a registrar; value is unformatted string
    - regt for a registrant; value is unformatted string
    - srv for service info; not yet implemented
- value may contain spaces

A signed short assertion is generated and verified over the unsigned short
assertion with a valid key for that assertion's zone. A signed short assertion
has the form "S valid-from valid-until cipher-number signature unsigned-assertion" where:

- cipher-number is an integer identifying the cipher algorithm
- signature is hex-encoded.
- valid-from is an ISO8601 timestamp
- valid-until is an ISO8601 timestamp

Signatures are generated over the concatenation of a stub signature (i.e.,
valid-from valid-until cipher-number) to an unsigned assertion.

A short query has the form:

"Q valid-until context subject objtype"

(Note that unlike RAINS queries, short queries can only have a single context
and object-type. This simplification may carry over into the protocol.)

### verification engine design {#verify}

The verification engine caches the current set of public keys used to verify
assertions in each zone the server knows about. It is fed delegation
assertions by the query engine when they are received, and may issue queries
using the query engine when missing a key needed to verify a signature chain.

It takes incoming assertions and verifies their signatures. It has the following entry points:

- `delegate(context, zone, cipher, key, until)`: add a delegation to the cache, called by the query engine for each delegation assertion received.
- `verify(assertion) -> assertion or nil`: verify an assertion. strip any signatures that did not verify. if no signatures remain, returns nil.
- `verify(shard) -> assertion or nil`: verify a shard. recursively verify contained assertions which have their own signatures. strip any signatures that did not verify. if no signatures remain, returns nil.
- `verify(zone) -> assertion or nil`: verify a shard. recursively verify contained shards and assertions which have their own signatures. strip any signatures that did not verify. if no signatures remain, returns nil.
- `reap()`: remove expired delegations. This is probably simply called by a goroutine waiting on a tick channel.

### data model marshaling and unmarshaling design {#datamodel}

looks like we have to write our own CBOR serialization/deserialization due to
two complications:

- RAINS requires canonical CBOR for signing that CBOR libraries may not honor.
- Moving RAINS to CSON, which might make sense, would require a CSON library, 
  which doesn't exist yet, but should integrate with the CBOR library.
- RAINS specifies integer keys for extensible maps for efficiency, and 
  supporting integers in structure tags requires special handling. 

One could/should hack an existing CBOR library to provide these two properties.

## rainspub design

`rainspub` takes input in the form of RAINS zonefiles (see 
[the zonefile definition](#zonefiles)) and a keypair for a zone, 
generates signed assertions, shards, and zones, and publishes these to a set 
of RAINS servers using the RAINS protocol.

Its design is fairly simple, based around a linear workflow:

- take as input a keypair, a zonefile, a set of server addresses, and sharding
  and validity parameters
- parse the zonefile into a set of unsigned assertions
- group those assertions into shards based on a set of sharding parameters
- sign assertions, shards, and zones with a validity specified by validity parameters
- connect to the specified servers and push the signed messages to them using the RAINS protocol

an authority server (in the traditional, DNS-like sense) is therefore
constructed by running `rainspub` and `rainsd` at the same time, with
`rainspub` pushing only to the colocated `rainsd`.

### zonefile Format {#zonefile}

todo: describe the rains zonefile format here. inspired by BIND zonefiles,
close to the wire format, and designed to be easily RDP-parseable.

## rainsclientlib and rainsdig design

todo: rainsdig should basically work like dig, output should look like a zonefile. it should probably use rainsclientlib.

## rainsfic design

`rainsfic` automatically generates input to `rainspub` in the form of zonefiles
("fictions") in order to build naming hierarchies for test purposes; as well
as scripts using `rainsdig` to simulate queries against these hierarchies. This
is designed both for benchmarking and stress and performance testing of the
RAINS software, as well as to explore the performance of different
arrangements of servers at different points in the namespace and query
generation parameter space.
