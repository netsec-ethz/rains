# Assertion cache

## Cache design decisions
- Assertions over which the server has authority are only removed when they expire. All other
  assertions are subject to a least recently used policy.

## Assertion requirements
- cache has a maximum size which is configurable (to avoid memory exhaustion of the server in case
  of an attack). It is not fix size to reduce the number of comparisons needed for checking that the
  new assertion is consistent with all already cached entries.
- In case the cache is full the least recently used assertion over which the server has no authority
  is removed from the cache. In case the authoritative assertions fill up the cache an error msg
  must be logged such that an operator can change the configuration.
- it must provide an insertion function which stores an assertion together with an expiration time
  to the cache (expiration time is necessary as we might want to store them for a shorter amount of
  time as they are valid. It is not possible to change the value directly as it is protected by the
  signature). It must also add this entry to the consistency cache.
- it must provide fast lookup of a set of assertions based on name, type, and zone (if any context
  is allowed) or a name, type, zone, and context. A set is returned such that the calling function
  can decide which entry it wants to send back according to a policy. Depending on a parameter flag
  it also returns expired assertions as part of the returned set (to allow answering queries with
  option 5 set).
- it must provide a reap function that removes expired assertions. This function must also remove
  the corresponding element in the consistency cache.
- it must provide a removal function which removes all assertions of a specific zone in case this
  zone misbehaved or sent inconsistent messages.
- all cache operations must be safe for concurrent access

## Assertion implementation
- lru strategy is implemented as a linked list where pointers to the head and tail of the list are
  accessible.
- on insertion or lookup of an assertion it is moved to the head of the list
- in case the cache is full the assertion at the tail of the list is removed.
- to allow fast lookups of assertions, two hash maps are used. The first hashmap is keyed by zone,
  name, and type. The value is a pointer to the second hashmap which is keyed by the context. The
  value points to a lru list node.
- a list node contains a set (safe for concurrent accesses) of objects containing an assertion and
  expiration time. Each object in the set must have the same zone, name, type, and context.
- sections over which this server has authority are not subject to lru removal.
