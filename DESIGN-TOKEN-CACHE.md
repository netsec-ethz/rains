# Token cache

## design decision
- The token cache is intended to prioritize delegation assertions which are necessary to verify
  signatures on previously received sections. This reduces the amount of time a section stays in a
  pending cache and hence, the response time is lower. 
- In case the cache is full new sections with signatures are dropped until it is not full anymore.
- An external mechanism is necessary to monitor the incoming delegation assertions and if it detects
  a DOS attack it blacklists the source of it. 

## token cache requirements
- cache has a fixed size which is configurable (to avoid memory exhaustion of the server in case of
  an attack).
- entries must be actively removed. 
- it must provide an insertion function which stores the query expiration and information about the
  entity to which the query was sent.
- it must provide a fast response to the question if a token is contained in the cache.
- it must provide a cleanup function that removes expired entries and logs information about the
  entity which did not respond (What information should we log such that we blame the right entity?)
- all cache operations must be safe for concurrent access

## token cache implementation
- to allow fast lookup a hash map is used. It is keyed by the token. The value is an object
  containing information about the destination and the expiration time of the query.
- the cleanup functions goes through the hashmap, logs and removes those entries that are expired.
  Be aware that if all entries of a map are queried they are returned in random order.