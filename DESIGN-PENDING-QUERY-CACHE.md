# Pending query cache

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
- How do we handle a query which accepts as a response any context? If there is already a query in
  the cache for a specific context, should we send a new query or put it to the existing one? 
  
## Pending query cache implementation proposal
1. We only remove an element from the cache after we have received an answer or the query has
   expired. The server chooses according to some policy an expiration time for the new query it
   sends to not have elements in the cache for extended periods of time. In case the original query
   is still valid but the query sent from this server to obtain an answer has expired then according
   to the server's policy we either:
   1. Remove the query from the cache and send a notification 504 message back to the querier.
   2. Leave the original query on the cache, send a new query and update the token in the cache to
      the value used for the new query and the validity time. Repeat this process at most x times 
      where x is configurable.
   3. A combination of both. Only resend if there is a new query asking for the same information.
   4. There might be other policies

   It should handle the case gracefully where the rains servers of an authority are down and the
   cache contains a lot of queries for this authority with a large expiration time such that it does
   not drop all other queries in the meantime while waiting for an answer of this authority.
   Especially when policy 3 is chosen.

2. We remove the least recently used query from the cache in case it is full.
    

## Pending query cache implementation decisions
- We choose suggestion 1. This enables as to log anomalies, increased load (which might be resulting
  from a Dos attack) and to specify different policies. The second proposal has the disadvantage
  that if the server receives a lot of queries for non cached content then non of them are directly
  answered as the query is already removed from the cache. When the originating server re-sends the
  query after it has expired it can be answered directly in case the information is still in the
  cache. This would certainly not be the true if the assertion cache is smaller than the pending
  query cache in which case this server will send a lot of messages but is never able to send a
  useful response (this can occur in a normal scenario as well as in an attack).

## Pending query cache requirements
- cache has a maximum size which is configurable (to avoid memory exhaustion of the server in case
  of an attack). It is not fix size because we want to be able to report when the cache reaches its
  limit to either increase the maximum size in the config, choose a different caching/pre-fetching
  strategy, or use this information in an external service to detect and mitigate a DOS attack.
- In case the cache is full new queries are dropped and notification messages are sent back.
- it must provide an insertion function which stores a query together with a validity time, the
  queries source and new queries destination server's addr [for DOS analysis, misbehavior], and the
  Token associated with the new query. It must return if there is already a query in the
  cache for the same information and the sent query is not yet expired. (Then the calling function
  can decide if it should resend a query). The return value must be computed fast.
- it must provide a fast lookup of the query based on query name or address, context and type.
- it must provide a fast lookup of all queries waiting for the answer of a query with Token t. (In
  case we get a notification message as a response we are then able to remove these entries from the
  cache)
- it must provide a reap function that removes expired entries and logs the source and destination
  server's addr.
- all cache operations must be safe for concurrent access

## Pending query cache implementation
- largely depends on which proposal we take
