# Query handling

## Design decisions
- Delegation queries are handled slightly differently because they are important for the system to
  run with minimal disruption.
- Note that if a rains server decides to do the lookup itself for a delegation query it might be
  blacklisted in case the server to which it starts the lookup is not responding and thus, it can
  also not respond in time.
- If a server forwards a query (answer is not cached), it does not forward subsequent queries asking
  for the same information. Instead it adds them to the entry of the first query (asking for the
  same information) in the pending query cache. In case the contained entry has expired, all waiting
  queries are removed from the cache and a new entry is made for the new query after it has been
  forwarded.
- If there is a positive answer for at least one of the queried types then this answer is returned
  i.e. a shard or zone is only returned if no assertion can be used as a full or partial answer to
  the query.

## Handle queries
The following two descriptions of how queries are handled are considering the case where only one
type is queried. In case the query contains multiple types then the first point is performed for
each type before processing the second point. If there is a positive answer for at least one of the
queried types then this answer is returned. In case there is no positive answer, the server starts a
look up in the negAssertion cache. It is sufficient to make a single lookup because assertions with
the same subjectName, subjectZone and context must be in the same shard or zone independent of the
type.

### Handle delegation queries
1. If the zoneKeyCache contains any information about the queried delegation the server answers with
   all delegations of the queried zone.
2. If there is a shard in range or a zone in the negAssertionCache answer with it.
3. Depending on the server's policy it either sends a redirect assertion back (if possible together
   with an IP assertion) loaded from the redirection cache or starts the lookup itself.
   - Send redirect: If there is a redirect assertion for the queried zone in the assertion cache
     then, if there is also an IP assertion for the queried zone in the cache it responds with both
     assertions, else it responds with the redirect assertion to the zone. In case there is no
     redirect assertion for the queried zone in the cache, it responds with a redirect to a root
     server.
   - Lookup itself: The server adds the delegation query to the pending query cache. (see design of
     callback function below on how it is further processed when the answer arrives) It then loads
     an IP address associated with the most specific redirect from the redirection cache. (In the
     worst case it has to ask a root server)

### Handle non-delegation queries
1. If the queried information is in the assertionCache answer with the shortest assertion.
2. If there is a shard in range or a zone in the negAssertionCache answer with the smallest section
   that answers the query. This can be a signed assertion contained in the shard or zone which has
   already been evicted from the assertion cache or a shorter shard in a zone. [I suggest to add a
   flag to shards and zones which indicate if their content is sorted. We can then use binary search
   on the content (in case the section is sorted) to quickly determine if the section contains a
   more specific section. The binary search must be upper bounded by log2(s.Content) in case the
   flag is set but the content is not sorted. This guarantees termination and it also allows to
   blacklist zones that send incorrect information]
3. Depending on the configuration the server either sends a redirect assertion back (if possible
   together with an IP assertion) or starts the lookup itself.
   - Send redirect: If there is a redirect assertion for the queried zone in the assertion cache
     then, if there is also an IP assertion for the queried zone in the cache it responds with both
     assertions, else it responds with the redirect assertion to the zone. In case there is no
     redirect assertion for the queried zone in the cache, it responds with a redirect to a root
     server.
   - Lookup itself: The server adds the delegation query to the pending query cache. (see design of
     callback function below on how it is further processed when the answer arrives) It then loads
     an IP address associated with the most specific redirect from the redirection cache. (In the
     worst case it has to ask a root server)

## Pending query callback function
When a rains server receives a section it must check the pending query cache to obtain queries which
are waiting for this answer. It first sets the value of a map which is keyed by the token to the
number of sections in the response message if it is larger than one. It is assumed that at this
point the section's signature has already been verified and that the received section is consistent.
The server checks with a configurable sampling rate that received non-delegation sections are really
an answer to the query. It checks all answers to delegation queries. It then proceeds as follows
(note that the server is not required to add the section to the cache):
- One Assertion with one or several objects, one shard or one zone (not redirect case):
  Lookup waiting queries in the pending query cache according to the tokens message and forward the
  message to the query's origin.
- Several assertions, shards, and or zones: Set the value of a map which is keyed by the token to
  the number of sections contained in the received message. After the section is added to the
  assertionCache, decrease the map count and in case the count is 0 look up and removes all pending
  queries for that token and send a response. Note that only the last section and cached sections
  are returned to the querier.
- Notification Message:
  Depending on the notification type different behavior. Resend query, drop pending queries silent,
  send response to dropped pending queries
- Redirect assertion(s): In case the assertion does not answer the query and contains a redirect
  object, the server can either start a lookup for the queried information and update the token
  in the pending query cache or return to all pending queries the assertion containing a redirect.
  The same applies in the case of several sections per message if the last processed section is an
  assertion not answering the query and containing a redirect.
