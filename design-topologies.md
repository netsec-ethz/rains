# Topologies

An assertion in RAINS must contain at least one signature to be valid. This
paradigm allows a user to check the validity of an assertion without having to
go through a recursive lookup (but he still needs all delegation assertions up
to the root). It is not only beneficial for a user but also for any entity using
or being part of the naming system. In this section, we are introducing several
topologies and strategies on how RAINS might be operated together with an
analysis pointing out the advantages and disadvantages of these approaches.
There is always a tradeoff between having smaller local servers and high
performance centralized servers. The advantage of local servers are a lower
latency due to the shorter network path and many cache hits as clients from the
same region speak the same language and will visit similar websites (based on
the same interests, news, etc.). But once you want to access a lesser known
website it is with high probability not in the cache. The centralized servers
have a much broader range of clients and thus, the probability of having a cache
hit on a lesser known website is certainly higher. [TODO CFE think more about
the privacy implications for each of the different models]

## Distributed centralized approach

All information is stored in each of several locations around the world. All
authorities push their assertions to these locations. A client is querying a
server from the closest location. Should I elaborate more, as there are so many
points against this approach?

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

## RAINS server with Memcached

Assuming that the sum of RAM an operator wants for all caches in a rains server
is larger than the maximum capacity of one server another architecture has to be
chosen. A rains server could be split up in three components. A component which
accepts pushed assertions, a memcached instance [7] (in-memory database), and a
component which accepts queries and answers to queries it has sent out. This
setup allows almost arbitrary high cache sizes as the RAM is distributed onto
several machines. Additionally, if the RAM requirements change during operation
new memcached servers can be added to or removed from the system without
interrupting the service. All servers answering client queries use the same
distributed caches and thus, have less cache misses. New servers are not slower
in answering queries than current once as they do not start with an empty cache.

- Issue: How does a client know which of the name servers are for answering
  queries and which are for pushing assertions. Probably two components are
  enough. A rains server in the foreground which instead of looking in its own
  RAM sends a memcached request to the distributed caching infrastructure. And
  the memcached servers in the background.

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

## Additional ideas to optimize the system and/or make it more private

- An authority over a zone which wants to reduce query delay in specific region
  could store its information in a content delivery network or in the cloud and
  serve client from a local server. This might be a temporal solution until a
  location is found or permanent in case an own location is too expensive. An
  alternative would be to push its information to local cache resolvers.

- A caching server could have a monitoring system which tracks for a given time
  period how many times an entry was queried. Then the most frequently used
  domains, e.g. top 10%, could be monitored and before an assertion expires a
  query will be sent preemptively.The query will be sent to the ip address of
  the server from which it got the previous entry. In case the ip address has
  changed in the meantime, the server can do a recursive lookup before the
  current entry expires to avoid a gap where this entry is not in the cache. Is
  it worth the extra effort?

- A client can have the possibility to decide which entries there should/must be
  present at the cache at all times and pays a certain amount for it. This
  amount could be relative to the number of other people wanting this entry in
  the cache. This approach improves privacy against an external observer as
  queries are not linkable to the recursive lookup anymore. The client's RAINS
  or DNS server knows its queries though. But without an anonymity network this
  is the case anyway. (compare this approach to sending a query to a large scale
  open resolver (Quad8, Quad9 or Quad1) where a large enough amount of queries
  are concurrently incoming such that an observer cannot distinguish from which
  it arrived)

## Bibliography

[1] How DNS works (26.06.18)
https://www.appliedtrust.com/resources/infrastructure/understanding-dns-essential-knowledge-for-all-it-professionals
[2] Google public DNS (26.06.18) https://developers.google.com/speed/public-dns/
[3] Quad9 IBM's public DNS (26.06.18) https://www.quad9.net/
[4] Cloudflare's public DNS (26.06.18) https://1.1.1.1/
[5] Blog about 1.1.1.1 (26.06.18) https://blog.cloudflare.com/announcing-1111/
[6] dnsperf (26.06.18) https://www.dnsperf.com/#!dns-resolvers
[7] Memcached (26.06.18) https://memcached.org/
[8] PNRP (30.06.18)https://en.wikipedia.org/wiki/Peer_Name_Resolution_Protocol
[9] Chord (30.06.18) http://nms.csail.mit.edu/papers/chord.pdf