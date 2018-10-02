# Simulation Framework

We are building a simulation framework to evaluate several aspects of RAINS and
to be able to compare it with other naming systems. Some of these simulations
can be used as benchmarks to demonstrate the improvements of newly implemented
optimizations against the previous state of the system. This framework will have
clearly defined input interfaces which must be implemented by the different data
sources.

## Requirements

- Each simulation must have a well defined input interface, a description what
  it simulates with the input data, and what the output is going to be.
- There is a configurable zone file generator which can be used when no real
  zone file data is available or when alternate name space arrangements are
  being tested.

## Zone characteristics

A zone has the following characteristics:

- Size: Number of assertions.
- Depth: How long its delegation chain is.
- Nonexistence proofs: How a zone organizes its nonexistence proofs.
- Dynamics: How often changes occur to the zone's content.
- Content: Distribution of assertion types.
- Content size: Length distribution of its assertions, shards and zones.

Some of these properties are correlated in most zones. e.g. a large zone size is
more dynamic and has a smaller depth, small zones use a zone as non existence
proofs while large ones are using shards, etc.

## Zone file generator(s)

## Query trace generator

## Experiments

1) Signing time of assertion, shard, pshard, zone according to their size and
   number (expected linear)
2) zonepub/rainspub latency for different zone sizes to do sharding and adding
   signatures. Small, medium and large zones.
3) space saving extend of pshards depending on the chosen bloom filter
   parameters and number of assertions. (expected more than linear)
4) use rainsd and replace b-root traffic to demonstrate that it can handle real
   world load. Send queries from single machine timed according to the trace to
   server over go channel. Have a separate channel for each zone authoritative
   server. On first use of a channel add extra delay to take connection setup
   into account.
5) Memory and CPU consumption of authoritative server under various load
   patterns
6) Memory and CPU consumption depending on mode of operation of a caching
   resolver.
7) Setup topology and measure overall bandwidth and query latency for each. For
   P2P use a round trip time distribution modeling hosts on the internet to
   approximate delay on each channel.
8) How does the number of resolvers influence query delay and bandwidth
   consumption starting from a centralized approach and going more and more to
   a P2P setting using the above mentioned distribution.

## Experimentation input

1) zonefile.
2) zonefile, sharding parameters.
3) shard, bloom filter parameters.
4) full payload packets data with timestamps.
5) query packets data with arrival timestamp.
6) full payload packets data with timestamps.
7) client-server ratio, P2P delay matrix, zonefiles, querytrace for each client.
   Clients connect to closest dns server, cluster latency map to find good
   places to put dns server.
8) same as 7)
