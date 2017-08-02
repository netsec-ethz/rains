# Token cache

## Design decision
- The token cache is intended to prioritize delegation assertions which are necessary to verify
  signatures on previously received sections. This reduces the amount of time a section stays in a
  pending cache and hence, the response time is lower.
- A Token is removed from the cache when the first message with this token arrives. In case several
  messages are sent in response to a delegation query only the sections of the first message are put
  on the priority queue.
- In case the cache is full new sections with signatures are dropped until it is not full anymore.
  An alarm is raised in case this cache is full.
- An external mechanism is necessary to monitor the incoming delegation assertions and if it detects
  a DOS attack it blacklists the source of it.

## Token cache requirements
- cache has a maximum size which is configurable (to avoid memory exhaustion of the server in case
  of an attack). Cache is maximum size because it must periodically go through its entries and
  delete and report back all expired elements to e.g. allow an external service doing blacklisting.
- entries must be actively removed.
- it must provide an insertion function which stores the query expiration and information about the
  entity to which the query was sent.
- it must provide a fast response to the question if a token is contained in the cache.
- it must provide a reap/alarm function that removes expired entries and logs the destination addr
  to which the query was sent and from which we did not get a response.
- all cache operations must be safe for concurrent access

## Token cache implementation
- to allow fast lookup a hash map is used. It is keyed by the token. The value is an object
  containing information about the destination and the expiration time of the query.
- the cleanup functions goes through the hashmap, logs and removes those entries that are expired.
  Be aware that if all entries of a map are queried they are returned in random order.