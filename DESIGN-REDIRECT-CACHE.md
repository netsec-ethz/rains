# Redirect Cache

## Design Decisions
- There must be a global configuration (policy) which determines when the server is following a
  redirect and when it forwards the redirect.

## Redirect cache requirements
- cache has a maximum size which is configurable (to avoid memory exhaustion of the server in case
  of an attack). It is not fix size because it is operationally important that this cache has enough
  capacity. In case the number of cache entries exceeds a configurable threshold an alarm must go
  off. To prevent false alarms, expired elements must be removed frequently.
- There must be a mechanism to report when an authority has more than a configurable amount of
  redirects in the cache (which could then be used for DOS defense).
- redirect assertions issued by the authority of the zone running the server and redirect to root
  server(s) will only be removed from the cache when they are expired. In case the authoritative
  redirect assertions fill up the cache an error msg must be logged such that an operator can
  change the configuration.
- redirects from other zones are either removed because they are part of the least recently used
  zone in case the cache is full or are expired.
- it must provide an two insertion functions. One that stores delegation or redirect names to the
  cache and another which adds connection information to such a name together with an expiration
  time. The assertions from which this information originates, must be logged.
- it must provide fast lookup of a set of connection information associated with redirect/delegation
  names for the queried zone.
- it must provide a reap function to delete expired elements.
- all cache operations must be safe for concurrent access

## Redirect cache implementation
- lru strategy is implemented as a linked list where pointers to the head and tail of the list are
  accessible.
- on insertion or lookup of a zone it is moved to the head of the list
- in case the cache is full all entries of the zone at the tail of the list are removed.
- to allow fast lookup several hash maps are used. The first hash map is keyed by the subjectZone.
  The value points to a lru list node.
- a list node contains a hash map keyed by the connection information. The value is the expiration
  time of the IP Assertion. It holds a lock and a deleted flag such that the reap function can
  delete this list node from the cache in a safe way. Optionally it could store the assertions
  containing the delegation and the IP addresses.
