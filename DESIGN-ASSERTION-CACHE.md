# Assertion cache

## Cache design decisions
- Assertions over which the server has authority are only removed when they expire. All other
  assertions are subject to a least recently used policy.
- Expired assertions are also returned such that it is possible to answer a query which has
  query option 5 (expired assertions are acceptable) set. 
  
## Assertion requirements
- cache has a fixed size which is configurable (to avoid memory exhaustion of the server in case of
  an attack).
- In case the cache is full the least recently used assertion over which the server has no
  authority is removed from the cache.
- it must provide an insertion function which stores an assertion together with an expiration time
  to the cache (expiration time is necessary as we might want to store them for a shorter amount of
  time as they are valid. It is not possible to change the value directly as it is protected by the
  signature).
- it must provide fast lookup of a set of assertions based on name, type, and zone (if any context
  is allowed) or a name, type, zone, and context. A set is returned such that the calling function
  can decide which entry it wants to send back according to a policy.
- it must provide fast lookup of a set of assertions based on a zone, context and name interval.
  This is necessary to check if a new shard or zone is consistent with the cached assertions. 
- it must provide a cleanup function that removes expired assertions.
- all cache operations must be safe for concurrent access

## Assertion implementation
- lru strategy is implemented as a linked list where pointers to the head and tail of the list are
  accessible.
- on insertion or lookup of an assertion it is moved to the head of the list
- in case the cache is full the assertion at the tail of the list is removed.
- to allow fast lookups of assertions, two hash maps are used. The first hashmap is keyed by zone,
  name, and type. The value is a pointer to the second hashmap which is keyed by the context. The
  value points to a lru list node.
- a list node contains a set (safe for concurrent accesses) of objects containing an assertion and a
  expiration time. Each object in the set must have the same zone, name, type, and context.
- to allow fast lookups of assertions for consistency checks. There is an additional hashmap keyed
  by zone and context. The value points to a list of assertions ordered according to their name.
  (Instead of an order list we could use a segment or interval tree) 
- sections over which this server has authority are not subject to lru removal.
