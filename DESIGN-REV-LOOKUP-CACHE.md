# Reverse lookup cache

## reverse lookup cache requirements
- cache has a fixed size which is configurable (to avoid memory exhaustion of the server in case of
  an attack). The size is counted over all binary tries.
- In case the cache is full the least recently used trie node is removed (over all tries).
- it must provide an insertion function which stores to a given context an addressAssertion or 
  addressZone.
- it must provide a fast reverse (name) lookup given an IP4 or IP6 address in CIDR format.
- in case of an inconsistent section, it must be possible to delete all entries with the same
  authoritative zone from the cache. (or less strict to only delete sections of the same
  authoritative zone and context?)
- it must provide a cleanup function that removes expired entries.
- all cache operations must be safe for concurrent access

## reverse lookup cache implementation proposal
1. There are two binary tries per context (one for IP4 and the other for IP6 reverse (name) lookup).
   We then also need a map keyed by context, where the value points to two trie roots. Each existing
   node of a trie stores a set of addressAssertions and addressZones.
2. There are two binary tries (one for IP4 and the other for IP6 reverse (name) lookup). At each
   existing trie node we need a map keyed by context. The map value points to an object containing a
   set of addressAssertions and addressZones issued for the given context.

## reverse lookup cache implementation decisions
- We decided to use the first proposal. Why? So that we can answer queries for different context in
  parallel? Is there a relatively easy way to not always lock the whole trie? (I think there is if
  removal of parts of the trie structure is forbidden, otherwise it should also be not that hard
  because the trie entries are not rearranged so if you lock a node and all nodes in the subtree are
  not locked by an other process one can safely delete or modify anything in the subtree by only
  holding the lock on the root.) 

## reverse lookup cache implementation
- To achieve an overall maximum number with lru strategy, a pointer to a lru list node is stored at
  each existing trie entry. The lru list node contains a set of addressAssertions and addressZones.
  This approach enables to delete the least recently used entry over all tries. Depending on which
  design proposal we choose, this might become more involved. 
- Binary tries are used to quickly find the longest prefix match.
- The tries are built dynamically (a full ipv6 trie is too large to be stored. It has more than
  2^128 entries. In a real setting it is sparse though).
