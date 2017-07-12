# Negative assertion cache

## Cache design decisions
- Shards and Zones over which the server has authority are only removed when they expire. All other
  shards and zones are subject to a least recently used policy.
  
## Negative assertion requirements
- cache has a fixed size which is configurable (to avoid memory exhaustion of the server in case of
  an attack).
- In case the cache is full the least recently used shard or zone over which the server has no
  authority is removed from the cache.
- it must provide an insertion function which stores a shard or zone together with a expiration time
  to the cache (expiration time is necessary as we might want to store them for a shorter amount of
  time as they are valid. It is not possible to change the value directly as it is protected by the
  signature).
- it must provide fast lookup of a set of shards and zones based on a name interval and zone (if any
  context is allowed) or a name interval, zone, and context. The interval is necessary to perform
  consistency checks between a new shard and all overlapping cached shards and zones. A set is
  returned such that the calling function can decide which entry it wants to send back according to
  a policy
- it must provide a cleanup function that removes expired entries.
- all cache operations must be safe for concurrent access

## Negative assertion implementation
- lru strategy is implemented as a linked list where pointers to the head and tail of the list are
  accessible.
- on insertion or lookup of a public key it is moved to the head of the list
- in case the cache is full the public key at the tail of the list is removed.
- to allow fast lookup two hash maps and interval trees are used. Interval trees can efficiently
  return all intervals stored in the tree which overlap with an input interval or point. The first
  hashmap is keyed by a zone. The value is a pointer to the second hashmap which is keyed by the
  context. The value points to a interval tree data structure. A stored interval in the tree is a
  lru list node where the interval of the list node is inherited from the contained shard or zone. 
- a list node contains a set (safe for concurrent accesses) of shards and/or zones which have the
  same subjectZone, context and interval.
- sections over which this server has authority are not subject to lru removal.
