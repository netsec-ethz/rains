# Query handling

## Design decisions
- Delegation queries are handled slightly differently because they are important for the system to
  run with less disruption.
- To avoid large memory consumption we do not enter shards and zones in the zoneKeyCache but instead
  only add the public key. There must be an incomplete counter for each zone such that we only use
  the delegation entries of this zone in a query response if all are present. The incomplete counter
  is increased every time we store a public key without a section (when the section is a zone or
  shard where the contained assertion is not signed). [editors note: update missing public key and
  cache design in case we decide to do this case. If not, update this document]
- Note that if a rains server decides to do the lookup by himself for a delegation query it might be
  blacklisted in case the server to which it starts the lookup is not responding and thus, it can
  also not respond in time.

## Handle delegation queries
1. If the queried delegation is complete in the zoneKeyCache answer with all delegations of the
   queried zone.
2. If there is a shard in range or a zone in the negAssertionCache answer with it.
3. Depending on the configuration the server either sends a redirect assertion back (if possible
   together with an IP assertion) or starts the lookup itself.
3. If there is a redirect assertion for the queried zone in the assertionCache then, if there is
   also an IP assertion for the queried zone in the cache it responds with both assertions or sends
   the query to the zone's rains server, else it responds with the redirect assertion to the zone or
   sends an IP query for the given redirect name to a root server. In case there is no redirect
   assertion for the queried zone in the cache, it responds with a redirect to a root server or
   starts the lookup at the root server.
4. If the server starts a lookup by itself (according to configuration) it adds the delegation query
   to the pending query cache. (see design of callback function below on how it is further
   processed)

## Handle non-delegation queries

## Pending query callback function
When a rains server receives a section it MUST check the pending query cache to obtain queries which
are waiting for this answer. It proceeds as follows (note that the server is not required to add the
section to the cache):
