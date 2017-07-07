# Reverse lookup cache

## Cache design decisions
- There are 2 binary trie per context (IP4 and IP6, one hashmap keyed by context, the value points
  to these two trie roots) and each existing node of a trie stores a set of addressAssertions and
  addressZones
- Alternative: There are 2 binary tries and at each node there is a hashmap keyed by context and the
  value points to an object containing a set of addressAssertions and addressZones
- We decided to use the first proposal. Why? So that we can answer queries for different context in
  parallel? Is there a relatively easy way to not always lock the whole trie? (I think there is if
  removal of parts of the trie structure is forbidden, otherwise it should also be not that hard
  because the trie entries are not rearranged so if you lock a node and all nodes in the subtree are
  not locked by an other process one can safely delete or modify anything in the subtree by only
  holding the lock on the root.)
- For each context we have a different binary trie to quickly find the longest prefix match. 
- How can we set an upper bound on the maximum number of entries. There should be a maximum number
  of entries over all binary tries as otherwise an attacker could just make up a lot of different
  contexts. To achieve an overall maximum number with lru strategy in case it gets full, one could
  add to each existing trie entry a pointer to a lru list node. A lru list node contains a set of
  addressAssertions and addressZones. This approach enables to delete the least recently used entry
  over all tries. 
- The tries are built dynamically to safe space (it is not possible to store a full ipv6
  trie. In a real setting it is sparse)
- 


## reverse lookup cache requirements


## reverse lookup cache implementation
