# Consistency cache

## Cache design decisions
- We have a separate cache for consistency checks because they are expensive. It also reduces the
  complexity of the assertion and negative assertion cache design. It allows to make consistency
  checks in parallel to answering queries as the write lock is not on the assertion or negative
  assertion cache (which increases efficiency).

## Consistency cache requirements
- cache has a maximum size which is the sum of the maximum size of the assertion and the negative
  assertion cache (to avoid memory exhaustion of the server in case of an attack). It is not fix
  size to reduce the number of comparisons needed for checking that a new section is consistent with
  all already cached entries.
- Every element in the assertion and negative assertion cache must also be present in the
  consistency cache and vice versa. The assertion and negative assertion caches are responsible to
  remove the corresponding entry from the consistency cache if they evict an entry in their cache.
- it must provide an insertion function which stores an assertion, shard or zone.
- it must provide fast lookup of a set of assertions, shards and zones based on a subjectZone,
  context and name interval. This is necessary to check if a new assertion, shard or zone is
  consistent with cached entries.
- it must provide a delete function that allows the assertion and negative assertion cache to also
  delete a corresponding entry in the consistency cache.
- all cache operations must be safe for concurrent access

## Consistency cache implementation
- to allow fast lookup a hash map and interval trees are used. Interval trees (or Augmented tree
  according to wikipedia) can efficiently return all intervals stored in the tree which overlap with
  an input interval or point. The hashmap is keyed by zone and context. The value points to a
  interval tree data structure. A stored interval in the tree is an assertion, shard or zone. The
  interval tree must support different elements with the same interval and report all of them in
  case a query is overlapping.
