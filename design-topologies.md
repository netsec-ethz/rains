# Topologies

An assertion in RAINS must contain at least one signature to be valid. This
paradigm allows a user to check the validity of an assertion without having to
go through a recursive lookup (but he still needs all delegation assertions up
to the root). It is not only beneficial for a user but also for any entity using
or being part of the naming system. In this section, we are introducing several
topologies and strategies on how RAINS can be operated. We also list some
desirable properties and what the tradeoffs are between them. In the end, we
place each topology/strategy in the tradeoff space and analyse the advantages
and disadvantages of each approach.

## Tradeoff space

To evaluate different topologies we first have to determine in which properties
a client, developer or operator is interested in. Secondly, we point out which
of these properties influence each other to figure out where the tradeoffs are
lying. Finally, we evaluate where to place the different topologies in this
tradeoff space. Depending on the operational requirements an operator can then
choose which topology to deploy (or a mixture thereof).

### Query Latency

Query latency determines the amount of time a client has to wait for an answer
to his query. The smaller the value the faster a client can start a connection
with the destination. The value can be expressed as mean, average or tail
latency.

### Scalability

Scalability gives an indication about how many clients or queries the system
deployed in a certain topology can support before it starts to drastically slow
down. This property can also express how graceful overload is handled i.e. how
clients experience an overload situation.  

### Assertion publishing complexity

A zone authority makes information about its zone accessible through its
authoritative servers. Depending on the topology and the method used there might
be different amount of steps involved in publishing the zone's information. E.g.
the number, location and task of the authoritative servers.

### Availability/Security (Client side)

A client expects the system to be highly available and to obtain correct
information from it. The harder it is to break the delegation chain or to
prevent the client to obtain an answer for his query the better the topology
performs in this metric.

### Robustness (authoritative side)

The difficulty for an attacker to prevent a zone authority to publish
information about its zone to the system determines the robustness of the
topology.

### Privacy

Depending on the topology the difficulty for an attacker to obtain private
information varies. This property measures how much effort a given attacker
model has to invest to gain a certain amount of information about a client.

### Troubleshooting complexity

Troubleshooting complexity measures the difficulty for an operator to determine,
locate and fix an error scenario.

### Cost

Cost states an estimate of the monetary cost each of the topologies has. It can
include how the costs are divided between the operators of the system and the
source of the cost such as electricity, location, number of operators etc. 

### Maintainability

Maintainability describes the effort operators have to invest to keep the system
running i.e. to update malfunctioning or old hardware, update the amount of
servers depending on the amount of queries, etc.

## Tradeoffs

In general, there is a tradeoff between serving each client from a close by
local server or from a larger, high performance and further away server. The
first approach requires the servers to be locally distributed at many different
places close to the clients where as in the second suggestion there are fewer
locations with more servers to which a larger group of clients send their
queries. The advantage of local servers are lower latency due to the shorter
network path and possibly many cache hits as clients from the same region speak
the same language and will visit similar websites (based on similar interests,
events, news, etc.). But once a client accesses a lesser known website it is
with high probability not in the cache. The more centralized servers have larger
caches and a much broader range of clients and thus, the probability of having a
cache hit will probably be higher. Next, we are listing the tradeoffs between
the above properties and why they occur.

- Cost vs Latency: Deploying additional/less servers closer to the clients.
- Cost vs Scalability: Deploy more/less servers
- Cost vs Availability: Having more/less redundant servers
- Cost vs Robustness: Having more/less authoritative servers and bandwidth
- Cost vs Privacy: Depending on the approach more servers are needed
- Cost vs Troubleshooting: Bad tools -> more work -> more operators
- Cost vs maintainability: Bad maintainability -> more operators
- Latency vs Security: More/less security checks influence latency
- Latency vs Robustness: less robust -> more failures -> partly higher latency
- Latency vs Privacy: Depending on the method, much higher latency (e.g. mixnet)
- Scalability vs Assertion publishing complexity: obvious
- Scalability vs Security: More defenses -> more machines&complexity -> less scalable 
- Scalability vs troubleshooting complexity -> obvious
- Scalability vs Maintainability: The larger the system the harder to maintain
- Assertion publishing complexity vs availability: more complex -> more things
  can go wrong -> reduced availability
- Assertion publishing complexity vs maintainability: obvious
- Availability vs privacy: no privacy -> no availability
- Availability vs Troubleshooting complexity: fix takes longer -> more downtime
- Robustness vs Privacy: more features -> more possible issues -> less robustness
- Robustness vs maintainability: more server/complex behavior -> less maintainable
- Privacy vs Troubleshooting complexity: more private -> harder to troubleshoot

## Centralized

### Setting

The centralized topology can be divided into two actors. The naming authorities
and the centralized resolver. The naming authorities provide the information to
the centralized resolver and all clients are sending their queries to the
centralized resolver. The centralized resolver is located at one location and
all traffic is going through it. To remedy a total outage the resolver can be
replicated at a different location which only takes over when the primary
resolver fails. The centralized resolver has a global view of the naming
ecosystem and performs consistency checks and validates the information it
receives. Several strategies can be used for the communication between the
naming authorities and the centralized resolver such as:

- Push only (by naming authority)
- Cache miss only (by centralized resolver)
- Fetch n most queried names before expiration, else only on cache miss

### Use case

- Small to mid size companies with few close locations

### Discussion

The centralized resolver is a single point of failure. All queries are going
through it which reduces its scalability. The latency corresponds to the
distance of the client to the resolver as long as the resolver can handle the
load. In a company setting where the queries are only coming from withing the
company, the amount of clients and queries are predictable and the necessary
hardware and cache size for the resolver can be estimated. Maintainability is
easy as everything is at a single location. As all the queries go through this
one resolver, the company can easily put policies in place which sites are
allowed to be accessed (by knowing the IP beforehand or changing the default
resolver a knowledgeable user can go around this access control). As the load is
predictable and the system is at a single location, monetary cost will be low.
The push only strategy only works when the company has a relationship with the
naming authority. The Cache miss only strategy is the simplest one but every
time an assertion expires, on the next request a recursive lookup has to be
performed which increases latency. Fetching updated assertions of the n most
queried names before they expire is a possible optimization heuristic to reduce
latency.

## Centralized controller with distributed caching resolvers

### Setting

This approach is similar to the centralized topology with the difference that
the centralized resolver is divided into two parts, one centralized controller
and many distributed caching resolvers. The centralized controller performs the
task of the centralized resolver in the previous topology. The distributed
caching resolvers reduce latency substantially for common query patterns. In
case of a cache miss, the caching resolver forwards the query to the centralized
controller which on a cache hit responds directly or else does a recursive
lookup.

### Use case

- Large size companies
- Companies with several locations that are geographically far apart

### Discussion

The same holds true as for the centralized topology. With the small difference
that maintainability is getting a bit harder as the servers are geographically
distributed and cost will be slightly higher. As the caching resolvers are not
performing recursive lookup themselves but go through the centralized
controller, latency is a bit higher. But with this approach the centralized
instance keeps control over the naming system and can still enforce its policy.
control. Depending on the query pattern it might even reduce latency for other
caching resolvers in case the centralized controller still has a cached answer.

## The DNS approach

RAINS can be operated the same way DNS is operated [1]. That means there are
caching and recursive name servers.  A client sends a query to the caching
server of its ISP. If there is a cache hit, the response is directly sent back
to the querier. Otherwise, the query is forwarded to the configured recursive
server which then sends a query to the authoritative server of the most specific
domain it already knows (information about the root name server are hard coded).
It repeats the previous step until it can answer the query and sends the answer
back to the caching server which then forwards it to the querier.

Advantages:

- Scalable
- Large scale deployment experiences from DNS

Disadvantages:

- If an entry is not in the cache, recursive lookup takes a long time
- New RAINS features are not used and RAINS' TCP connection is slower than DNS'
  UDP
- An attacker might be able to link a new connection with a recursive lookup and
  thus, finds out about the querie's content even though the connection between
  client and caching server is over TCP

## Large open DNS resolvers

In recent years, large tech companies started deploying open recursive DNS
resolvers such as Google's and Cloudflare's public DNS [2,3], or IBM's Quad9
[3]. These companies hope that users are going to use their DNS resolver instead
of the user's ISP's one. They argue that they value the user's privacy more and
are more secure by not resolving names they suspect being malicious. Due to
their size they are able to gather better information about malicious domains
and thus, are more accurate than most ISPs. Instead of having a large number of
distributed independent DNS resolver, in this approach there are only few large
DNS resolvers highly replicated around the world to reduce the latency for their
clients. RAINS could take this approach in the beginning to allow everyone to
perform name resolution even if the client's ISP does not yet support RAINS.

Advantages:

- Scalable?
- Very fast [6]. As lots of people are using this resolver the probability that
  your query's answer is cached is high. The client is still connecting to a
  local instance which likely contains local names.
- Large scale deployment experiences from some large tech companies
- You trust one large tech company to value your privacy
- Higher security
- Facilitates initial deployment besides DNS

Disadvantages:

- In straight forward copying this approach the new RAINS features are not used
  and RAINS' TCP connection is slower than DNS' UDP.
- The operator of this large resolver learns all requests of all its users. A
  user just has to trust the operator to not misusing his data.

## Large delegation resolvers

In this scenario, each ISP still operates naming servers. Instead of just having
the root where a recursive lookup starts in case the local ISP does not have the
queried information, there is a third type of server called delegation resolver.
These delegation resolver only store delegations. They could have the same
architecture as a RAINS server but only accept delegation assertions or they
might have more specialized design e.g. using memcached (see next subsection).
In this approach the main idea is that authoritative servers push their
delegations to the delegation resolver such that all delegations up to the root
are present. A recursive resolver would then, instead of querying first the
root, query a delegation resolver which then answers with all necessary
delegations in the normal case. This reduces a recursive lookup to just one
query to a delegation resolver and one query to the authoritative server. But
since the delegation assertions higher up in the hierarchy are probably cached
anyway in the recursive resolver and it starts the lookup at the most specific
known information it probably sends out not more than two queries anyway in most
cases. This system could be funded by authoritative entities which pay some
amount to have their delegations accepted and thus, reduce recursive lookup for
their zone.

Advantages:

- Faster recursive lookup

Disadvantages:

- Cost
- Probably no benefits in most settings

## Peer to peer network

Instead of having large entities which operate high performance rains servers
all over the world, an entry could be distributed among several rains servers of
different authorities (optimally in different parts of the world to reduce
latency). Similar to PNRP [8] or chord [9].This approach distributes the load
over many different servers providing the naming service. The popularity of a
domain determines how much it is distributed (otherwise, the server responsible
for google.com would certainly break down). Each AS (ISP) would be one peer.
Based on the used hash function it is clear for each client where to find an
entry. Based on the highly dynamic behavior of the system the entries might
change too often. It is also doubtable that such a system scales to the
requirements of a global naming system. Based on the knowledge from where an
entry is served, it becomes easier for an attacker to target certain domains and
just DDoS those servers which are responsible for the targeted domain. It is
especially critic for small domains as they are served only from few servers.

## Hybrid between peer to peer and caching

Cache the most queried entries in a local cache to reduce latency but still
benefit from the easier lookup based on the known location of an entry. The
caching also reduces the impact of DDoS attacks target on those servers
responsible for serving this entry. [TODO CFE elaborate more on this approach]

## Bibliography

[1] How DNS works (26.06.18)
https://www.appliedtrust.com/resources/infrastructure/understanding-dns-essential-knowledge-for-all-it-professionals
[2] Google public DNS (26.06.18) https://developers.google.com/speed/public-dns/
[3] Quad9 IBM's public DNS (26.06.18) https://www.quad9.net/
[4] Cloudflare's public DNS (26.06.18) https://1.1.1.1/
[5] Blog about 1.1.1.1 (26.06.18) https://blog.cloudflare.com/announcing-1111/
[6] dnsperf (26.06.18) https://www.dnsperf.com/#!dns-resolvers
[8] PNRP (30.06.18)https://en.wikipedia.org/wiki/Peer_Name_Resolution_Protocol
[9] Chord (30.06.18) http://nms.csail.mit.edu/papers/chord.pdf