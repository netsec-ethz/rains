# Pending signature cache

## Cache design decisions
- This cache is used in case the server does not have a cached public key to check a signature. It
  allows to buffer the section so that the processing go routine can handle another section from the
  queue and does not have to wait until the answer arrives.
- When a new delegation assertion arrives, then the server checks for sections in the cache waiting
  for this public key and starts processing them. In case a shard or zone arrives, the server looks
  up those sections in the cache waiting for the answer according to the token of the message and if
  the shard or zone contain the public key, starts processing them or drop them otherwise. (A
  section is dropped if it is signed by a private key for which the corresponding public key is not
  yet asserted by the super-ordinate zone)
- If this server has already sent a query to obtain the needed public key but has not yet gotten an
  answer, then the current query is added to the cache together with the token of the already sent
  query. No new query is sent again to the other server except the sent query has already expired.
- The maximum cache size sets an upper bound for the number of sections waiting for a public key. Be
  aware that the maximum size of the active Token cache sets the upper bound on how many queries for
  public keys can simultaneously be issued by this server. If the active Token cache is full and the
  section needs a not yet queried public key it gets dropped even when there is space in the pending
  signature cache. An alarm is raised when this cache reaches its capacity.
- Sections issued by rainsPub (over which the server has authority) are not removed from the cache.
  The query is reissued after expiration until an answer is received or the section is expired.

## Pending signature cache requirements
- cache has a maximum size which is configurable (to avoid memory exhaustion of the server in case
  of an attack). It is not fix size because it is operationally important that this cache has enough
  capacity. In case this cache is full an alarm must go off. To prevent false alarms, we remove
  expired elements.
- In case the cache is full all queries waiting for the least recently queried public key are
  removed from the cache except for sections published by the own zone (via rainsPub).
- it must provide an insertion function which stores a section together with the expiration time and
  token of the sent query to the cache. It must return if there is already a section in the cache
  waiting for the same public key and if the sent query is not yet expired. (Then the calling
  function can decide if it should resend a query). The return value must be computed fast.
- it must provide a fast lookup of the sections which wait for a public key from a given zone,
  context, algorithm identifier, and key phase. (the last two are only necessary if we can specify
  it in a query)
- it must provide a fast lookup of the sections which wait for the answer of a query with Token t.
  (In case we get a notification message as a response we are then able to remove these entries from
  the cache)
- it must provide a cleanup function that removes expired entries.
- all cache operations must be safe for concurrent access

## Pending signature cache implementation
- lru strategy is implemented as a linked list where pointers to the head and tail of the list are
  accessible.
- on insertion or lookup of a public key it is moved to the head of the list
- in case the cache is full the public key at the tail of the list is removed.
- to allow fast lookup two hash maps are used. The first is keyed by the tuple subjectZone, context,
  signature algorithm type, and key phase. (the last two are only necessary if we can specify it in
  a query). The second is keyed by the token used in the sent query. The value is a pointer to the
  corresponding list node.
- a list node contains a set (safe for concurrent accesses) of sections waiting for the public key,
  an expiration time, and a token. (the token is needed to remove the entry from the second hashmap
  in case of removal)
- sections over which this server has authority are not subject to lru removal. They are stored in a
  separate list.
