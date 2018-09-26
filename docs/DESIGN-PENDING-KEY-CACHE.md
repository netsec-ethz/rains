# Pending key cache

## Cache design decisions
- This cache is used in case the server does not have a cached public key to check a signature. It
  allows to buffer the section so that the processing goroutine can handle another section from the
  queue and does not have to wait until the answer arrives.
- When a new delegation assertion arrives, then the server checks for sections in the cache waiting
  for this public key and starts processing them. In case a shard or zone arrives, the server looks
  up those sections in the cache waiting for the answer according to the token of the message and if
  the shard or zone contain the public key, starts processing them or drop and log them otherwise.
  (A section is dropped if it is signed by a private key for which the corresponding public key is
  not yet asserted by the super-ordinate zone)
- A server can only resend a delegation query when the previous one has expired. This assures that a
  server does not get flooded with delegation queries e.g. after it rolled over a key.
- The maximum cache size sets an upper bound for the number of sections waiting for a public key.
  The server can be configured that sections from certain zones and contexts are not affected by
  this upper bound.
- In case the cache is full new sections with signatures are dropped until it is not full anymore.
  An alarm is raised in case this cache is full.
- The pending key cache maintains a token map which is intended to prioritize sections in response
  to a delegation query. This reduces the amount of time a section stays in the pending key cache
  and hence, the response time is lower.
- A Token is only removed from the cache if the sent query has expired or if all pending sections
  are answered.
- The server must log every section that gets dropped together with the destination which failed
  to send a delegation assertion in time.
- The cache does not check for each incoming assertion if the token is in the pending key cache. (It
  is assumed that the server who has sent the pending section has all the public keys to verify this
  section and it does not respond with a redirect or a delegation assertion which is intended to
  show this server where to ask for the public key (Note that it is fine for the other server to
  forward this query and let another server respond to it) If the assumption does not hold, then
  after the query has expired the pending sections are dropped and appropriate information is
  logged).


## Pending key cache requirements
- Cache has a maximum size which is configurable (to avoid memory exhaustion of the server in case
  of an attack). It is not fix size because it is operationally important that this cache has enough
  capacity. In case this cache is full an alarm must go off. To prevent false alarms, we remove
  expired elements.
- It must provide an insertion function which stores a section together with the ConnInfo from where
  we received it and its token to the cache. It returns if a new delegation query should
  be sent. It logs if the section is dropped in case the cache is full.
- It must provide a fast lookup of the sections (together with ConnInfo and Token) which wait for a
  public key according to the public key's zone, context, algoType and phase. These sections are
  removed from the cache. In case all sections of the public key's zone and context are answered by
  it, the corresponding token is removed from the cache.
- It must provide a fast lookup of the sections (together with ConnInfo and Token) corresponding to
  the query's token. The query's token and sections are removed from the cache (This function is intended
  for the case when a shard or zone is received in response to a delegation query).
- It must provide a reap function that removes expired tokens and section. It logs all removed
  sections and the connection information to which the delegation query was sent.
- It must provide a remove function which deletes all sections from the cache corresponding to a
  given token and logs it (In case e.g. a negative result or noAssertAvail is received).
- It must provide a function that returns if a token is in the cache to allow prioritization of
  responses to delegation queries.
- All cache operations must be safe for concurrent access

## Pending key cache implementation
- Three kind of hash maps are used for fast lookup of information. The first is keyed by token and
  points to a cache object. The second is keyed by zone and context and points as well to a cache
  object. The third kind is in the cache object and is keyed by algorithm type and phase and it
  points to a set of sections which are waiting for a public key matching the second and third hash
  maps' keys (The set is implemented as a hash map keyed by the hash of a section)
