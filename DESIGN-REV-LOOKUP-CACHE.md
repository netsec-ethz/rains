# Reverse lookup cache

## reverse lookup cache requirements
- cache has a fixed size which is configurable (to avoid memory exhaustion of the server in case of
  an attack). The size is counted over all binary tries.
- In case the cache is full the least recently used trie node is removed (over all tries).
- it must provide an insertion function which stores to a given context an addressAssertion or 
  addressZone. This function must check that the new entry is consistent with elements currently in
  the cache (this can easily be done by checking the subtree of the node at which the new entry will
  be inserted)
- it must provide a fast reverse (name) lookup given an IP4 or IP6 address in CIDR format.
- in case of an inconsistent section, it must be possible to delete all entries with the same
  authoritative zone from the cache.
- it must provide a function for consistency check.
- it must provide a cleanup function that removes expired entries.
- all cache operations must be safe for concurrent access

## reverse lookup cache implementation proposal
1. There are two binary tries per context (one for IP4 and the other for IP6 reverse (name) lookup).
   A map keyed by context is required to look up the two trie roots. Each existing
   node of a trie stores a set of addressAssertions and addressZones.
2. There are two binary tries (one for IP4 and the other for IP6 reverse (name) lookup). At each
   existing trie node we need a map keyed by context. The map value points to an object containing a
   set of addressAssertions and addressZones issued for the given context.

## reverse lookup cache implementation decisions
- We decided to use the first proposal because contexts are expected to appear rarely. It also
  allows to have multiple trie root locks at the same time (one per zone). It is ok to lock the trie
  root for insertion and removal as both operation are expected to happen rarely.

## reverse lookup cache implementation
- To achieve an overall maximum number with lru strategy, a pointer to a lru list node is stored at
  each existing trie entry. The lru list node contains a set of addressAssertions and addressZones.
  This approach enables to delete the least recently used entry over all tries.
- Binary tries are used to quickly find the longest prefix match.
- The tries are built dynamically (a full ipv6 trie is too large to be stored. It has more than
  2^128 entries. In a real setting it is sparse though).
- The generic trie structure should allow bits to be taken k at a time (for 2^k children per node),
  in order to account for v6 sparseness.
