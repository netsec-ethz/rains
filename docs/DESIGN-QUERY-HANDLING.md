# Query handling

## Design decisions
- Delegation queries are answered with all delegation assertions. All other queries are answered
  according to a configured policy.
- If a server forwards a query (answer is not cached), it does not forward subsequent queries asking
  for the same information. Instead it adds them to the entry of the first query (asking for the
  same information) in the pending query cache. In case the contained entry has expired, all waiting
  queries are removed from the cache and a new entry is made for the new query Before it is
  forwarded.
- If there is a positive answer for at least one of the queried types then this answer is returned
  i.e. a shard or zone is only returned if no assertion can be used as a full or partial answer to
  the query.

## Handle incoming queries
1. For each queried type look up in the assertion cache if there is an answer and choose one
   according to some policy. If complete or partial information is found, answer with it. In case
   of a delegation query the response contains all cached delegation assertions.
2. If there is a shard in range or a zone in the negAssertionCache answer with the smallest section
   that answers the query. This can be a signed assertion contained in the shard or zone which has
   already been evicted from the assertion cache or a shorter shard in a zone. (This check is cheap
   as the contained sections are sorted (binary search)).
3. If still no answer is found, the server adds the query to the pending query cache and forwards
   the query to a predefined server or starts a iterative lookup itself depending on its policy.

## Pending query callback function
When a rains server receives a section it must check the pending query cache to obtain queries which
are waiting for this answer. It proceeds as follows:
- Check if the received section's token is in the pending query cache and get the query.
  - Yes: Is the section answering the query? (a zone and a shard in range always answer the query)
    - Yes: Is the section an assertion?
      - Yes: Add the assertion to the answer list in the pending query cache. Wait a configurable
        waiting time. GetAll answers from the cache and send them back if the last answer was added
        by me. Remove the entry from the pending query cache.
      - No: Does the shard or zone contain an assertion answering the query?
        - Yes: Remove the entry from the pending query cache and send the assertion back.
        - No: Remove the entry from the pending query cache and send the shard or zone back.
    - No: Does the assertion contain any of these types: ip4, ip6, deleg, redir?
      - Yes: Is iterative lookup allowed?
        - Yes: Start an iterative lookup by sending a query to the appropriate server. Update the
          Token in the pending query cache to the new token from this query.
        - No: Remove entry from the pending query cache and answer them with a AssertNotAvail
          notification. Log that the received answer to the query cannot be used to answer it.
      - No: Remove entry from the pending query cache and answer them with a AssertNotAvail
        notification. Log that the received answer to the query actually not answered the query.
  - No: return

