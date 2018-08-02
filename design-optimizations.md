# Optimizations and deployment considerations

## Optimizations

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

## Deployment considerations

### RAINS server with Memcached

Assuming that the sum of RAM an operator wants for all caches in a rains server
is larger than the maximum capacity of one server another architecture has to be
chosen. A rains server could be split up in three components. A component which
accepts pushed assertions, a memcached instance [1] (in-memory database), and a
component which accepts queries and answers to queries it has sent out. This
setup allows almost arbitrary high cache sizes as the RAM is distributed onto
several machines. Additionally, if the RAM requirements change during operation
new memcached servers can be added to or removed from the system without
interrupting the service. All servers answering client queries use the same
distributed caches and thus, have less cache misses. New servers are not slower
in answering queries than current ones as they do not start with an empty cache.

- Issue: How does a client know which of the name servers are for answering
  queries and which are for pushing assertions. Probably two components are
  enough. A rains server in the foreground which instead of looking in its own
  RAM sends a memcached request to the distributed caching infrastructure. And
  the memcached servers in the background.

### Cloud

Having rains servers in the cloud gives an operator more flexibility. Depending
on how many requests are incoming the number of servers can be dynamically
adapted. Loading the most queried assertions from a file or another rains server
on startup helps to make this server faster more efficient as many recursive
lookups can be prevented. One of the possible downsides is that you must trust
the cloud operator to do a good job and that he makes sure that there are no
(or only very limited) disruptions.

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

## Bibliography

[1] Memcached (26.06.18) https://memcached.org/