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

Some of these properties are currently correlated in most zones. e.g. a large
zone size is more dynamic and has a smaller depth, small zones use a zone as non
existence proofs while large ones are using shards, etc.

## Zone file(s) generator

Due to lack of data and to experiment with new features requiring additional
data, we need a way to generate zonefiles for our experiments that are close to
reality. For large scale experiments, we need a zonefiles generator which
creates a configurable amount of zonefiles according to a distribution that
models the size/type of zones in the Internet. There are around 340 Million
domains registered at the 1500 top level domains (TLDs) [1,2]. 150 Million are
registered each at country-code TLDs and at .com together with .net. Most of the
TLDs delegate parts of their namespace directly to customers, resulting in many
small SLDs. A few TLDs, such as the uk, organize their SLDs according to the
type of entity registering like academia and companies. There, the TLD zone is
small but the SLD zones are large and contain many delegations to clients which
are small again. ICANN publishes monthly reports of each TLD with some
statistics about their operations [3] which we could use to model our zonefiles
and query traces. As a rough approximation of the depth of the zones we can use
a Zipf distribution with N = 10 and s = 4 where N is the max depth and s
represents the exponent. In each depth there are some large delegation zones,
some middle sized delegation zones (e.g. companies or institutions that have for
each division an own domain) and some small leaf zones (e.g. small businesses
and private websites). The ratio between these kind of zone types varies
depending on the zones' depth.

There will be four kinds of zonefile generators. A generic one that is highly
configurable and one for each kind of zone type (small, middle, large) with
reasonable default values. The name of the zone itself is an input parameter as
there must be a delegation to it in the superordinate zone. The names within a
zone are taken from a dictionary. If there is a distribution of the domain name
length, it could be used instead to generate names accordingly as for most
experiments the length is more important than the content as long as it is
unique. The dynamics of a zone is not part of the zonefile generator. In case it
is need there will be a zonefile modifier which alters the input zonefile
according to a dynamics parameter.

## Query trace generator

There are two different modes we want to simulate which ask for different
information in the query trace(s). One where we evaluate the performance of a
server and one where we evaluate the characteristics of different topologies.

### Server performance

To test the performance of a server, the delay to the querier does not matter
and thus, his identity does not as well. We need a distribution of durations
which describe when the next query arrives (query inter arrival time) and a
distribution of how many times a name is queried.

For the first we can use a poisson distribution for the amount of queries that
will arrive in a given time interval assuming that the queries arrival time are
independent of each other and that there is a constant rate per interval. The
first assumption is given due to the large diversity of clients sending requests
to a naming server while for the second one, it is pretty stable during the week
with a drop on the weekend according to [4]. But the granularity of [4] is the
average per day. There is certainly a diurnal pattern as well and it is unclear
how bursty it is.

As for the second distribution we can use a Zipf distribution. The Zipf's law
state that the frequency of any word is inversely proportional to its rank in
the frequency table [5]. This is in line with the fact, that there are few very
popular web sites, some medium ones and a vast majority of infrequently visited
ones.
 
### Topology characteristics

As in the previous example, we need a distribution of query names. As a slightly
simplified view, we can use the same zipf distribution as above. For a more
accurate model, we would need to have better measurement tools and data. Next we
have to distribute these queries to a number of clients. Then we have to
generate query traces for each of these clients with timestamps and destination
addresses. The timestamps will be chosen uniformly at random over the
experimentation interval to get an overall balanced load. The destination
address will be determined by the closest resolver a client has access to.

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

## Bibliography
[1] number of TLDs https://www.iana.org/domains/root/db  
[2] domain name statistics https://www.verisign.com/en_US/domain-names/dnib/index.xhtml  
[3] statics about number of queries per month per naming authority etc. https://www.icann.org/resources/pages/registry-reports  
[4] Number of queries per second https://www.nic.ch/statistics/dns/
[5] Zipf's law https://en.wikipedia.org/wiki/Zipf%27s_law
