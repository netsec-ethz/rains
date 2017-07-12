# Reverse lookup cache

## Cache design decisions
- This cache is used in case the server does not have a cached answer in response to a query. It 
  allows to buffer the query so that the processing go routine can handle another section from the 
  queue and does not have to wait until the answer arrives.
- When a new assertion, shard, zone, addressAssertion or addressZone arrives, the server sends a
  response to all cached queries for which the new section is an answer to.
- If this server has already sent a query to obtain information needed for the current query but has
  not yet gotten an answer so far for the same information, then the current query is added to the cache
  together with the token of the already sent query. No new query is sent again to the other server
  except the previous query has already expired.
  
## reverse lookup cache implementation proposal
1. We only remove an element from the cache after we have received an answer or the query has
   expired. In this case the server must be able to decide the query expiration time it sends to not
   have elements in the cache for extended periods of time. In case the original query is still
   valid but the query sent from this server to obtain an answer has expired then:
   1. Remove the query from the cache and send a notification message back to the sender.
   2. Leave the original query on the cache, send a new query and update the token in the cache to 
      the value used for the new query. Repeat this process at most x times (x is configurable).
   3. A combination of both. Only resend if there is a new query asking for the same information.
   It must be guaranteed that if the rains servers of an authority are down and the cache contains
   only queries for this authority with a large expiration time that it does not keep these entries
   for a long time and drop all other queries in the meantime.
2. We remove the least recently used query from the cache in case it is full. This has the
   disadvantage that if the server receives a lot of queries for non cached content then non of them
   are directly answered as the query is already removed from the cache. When the originating server
   re-sends the query after it has expired it can be answered directly in case the information is
   still in the cache. This would certainly not be the true if the assertion cache is smaller than
   the pending query cache in which case this server will send a lot of messages but is never able
   to send a useful response (this can occur in a normal scenario as well as in an attack). 

## reverse lookup cache implementation decisions
- 

## reverse lookup cache requirements
- cache has a fixed size which is configurable (to avoid memory exhaustion of the server in case of
  an attack).
- In case the cache is full [depends on chosen proposal]
- it must provide an insertion function which stores a query together with a validity time to the
  cache. (In case we decide for lru strategy (proposal 2) then we need to store additional
  information to be able to cleanup). It must return if there is already a query in the cache for
  the same information and the sent query is not yet expired. (Then the calling function can decide
  if it should resend a query). The return value must be computed fast.
- it must provide a fast lookup of the query based on query name or address, context and type.
- it must provide a fast lookup of all queries waiting for the answer of a query with Token t. (In
  case we get a notification message as a response we are then able to remove these entries from the
  cache)
- it must provide a cleanup function that removes expired entries.
- all cache operations must be safe for concurrent access

## reverse lookup cache implementation
- largely depends on which proposal we take
