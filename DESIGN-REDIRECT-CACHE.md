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
- it must provide an insertion function which stores to a zone a map from redirection names to
  objects containing IP addresses of these names, pointers to the assertions containing these
  information, and an expiration time.
- it must provide fast lookup of a set of IP addresses associated with redirect names for the
  queried zone.
- it must provide a reap function to delete expired elements.
- all cache operations must be safe for concurrent access

## Redirect cache implementation
- lru strategy is implemented as a linked list where pointers to the head and tail of the list are
  accessible.
- on insertion or lookup of a zone it is moved to the head of the list
- in case the cache is full all entries of the zone at the tail of the list are removed.
- to allow fast lookup several hash maps are used. The first hash map is keyed by the subjectZone.
  The value points to a lru list node.
- a list node contains a hash map keyed by redirection name. The value is an object containing a set
  of IP addresses associated with the hash maps' keys, the zone and pointers to assertions from
  which this information was taken from. (The zone value is necessary to update both hash maps when
  an entry is removed)
