# Key caches

## Key caches design decisions
- It must be possible to have one or multiple key rollover(s) during the validity period of a
  section. Thus, it must be possible to store several public keys for the same context, subjectZone,
  signature algorithm tuple.
- This cache should never be full. Otherwise we might not be able to verify the signature chain of
  all sections contained in the cache.

## Zone key cache requirements
- cache has a maximum size which is configurable (to avoid memory exhaustion of the server in case
  of an attack). It is not fix size because it is operationally important that this cache has enough
  capacity. In case the number of cache entries exceeds a configurable threshold an alarm must go
  off. To prevent false alarms, expired elements must be removed frequently.
- There must be a mechanism to report when an authority has more than a configurable amount of
  public keys in the cache (which could then be used for DOS defense).
- public keys received from explicitly specified servers (e.g. issued by the authority of a zone and
  published via rainspub) will only be removed from the cache when they are expired. In case these
  'special' delegation assertions fill up the cache an error msg must be logged such that an
  operator can change the configuration.
- a public keys is either removed because it is the least recently used in case the cache is full or
  when it has expired.
- it must provide an insertion function which stores a public key together with its context, zone,
  and a pointer to the delegation assertion from which the public key was extracted. The pointer to
  the delegation assertion can be used to proof its authenticity.
- it must provide fast lookup of a zone key together with a pointer to the containing assertion
  based on subjectZone, context, algorithm type, and phase id. It only returns valid public keys.
- it must provide a reap function to delete expired elements or in case the cache is full the least
  recently used public key.
- all cache operations must be safe for concurrent access

## Zone key cache implementation
- lru strategy is implemented as a linked list where pointers to the head and tail of the list are
  accessible.
- on insertion or lookup the zone key is moved to the head of the list
- in case the cache is full the zone key at the tail of the list is removed.
- to allow fast lookup a hash map keyed by subjectZone, algorithmType and key phase is used. The
  value points to a lru list node.
- a list node contains an object containing a set of public keys matching the hash map's keys, the
  zone, the context, and a pointer to the delegation assertion. (The context and zone value is
  necessary to update the hash maps when an entry is removed)

## Zone key cache locking
[editors note: update the locking design after the cache is adapted to the new design]
- we use read/write mutex locks on three different levels. We chose r/w locks over normal locks as
  most accesses are reads. The fourth is a normal lock (there are only writes when the update
  function returns if the cache reached its maximum size).
  1. is used to protect the first hashmap keyed by zone and the lru list accesses.
  2. is used to protect the second hashmap keyed by publicKeyID
  3. is used to protect the data object itself containing the zone and a set of public keys
  4. is used to protect the public key count
- on lookup and insert the first three locks are called one after another while the current lock is
  freed before the next is obtained. At the end of an insertion the lock on the public key count is
  used to increase the counter.
- to delete an entry it must first be looked up top down and then will be deleted bottom up. If e.g.
  the last public key is removed then a deleted flag is set on the object and the lock of the hash
  map pointing to it is obtained (notice that we still hold the lock on the object). We do not run
  into a deadlock because every lookup process releases the lock on the hash map before it obtains
  the lock on the object. The deleted flag is necessary such that a process waiting on the object's
  lock does not add a public key to it after the previous process removed the pointer to this object
  from the hash map (which makes it unaccessible)
- Never delete an entry top down otherwise we could run into a deadlock.

## Extra key cache requirement and implementation
- similar to the zone key cache with the only difference that instead of the phase identifier, an
  extra key has a key space identifier.

## Infrastructure key cache requirement and implementation
- depends on how infrastructure keys are used. This is not yet specified.
