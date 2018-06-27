# Topologies

An assertion in RAINS must contain at least one signature to be valid. This
paradigm allows a user to check the validity of an assertion without having to
go through a recursive lookup (but he still needs all delegation assertions up
to the root). It is not only beneficial for a user but also for any entity using
or being part of the naming system. In this section, we are introducing several
topologies and strategies on how RAINS might be operated together with an
analysis pointing out the advantages and disadvantages of these approaches.

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