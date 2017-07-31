# Missing public key

## Design decisions
- The callback function for the pending sections is triggered by a query response as well as a
  delegation assertion which matches the zone.
- We do not keep state how many times we issued a query for a given zone. We repeat it until the
  entry expires (which is the minimum of the query expiration time and a configurable maximum). In
  case a server does not specify a maximum expiration time, a malicious entity could send
  alternating redirects from two of its servers and without an expiration for the query the server
  would ask them infinitely.
- The communication partner is either another rains server or rainspub. If the public key is
  missing the server first has to determine where it should send a delegation query to. One approach
  is to always send the delegation query to the entity that has sent the section. For a rains server
  this should in most cases result in a positive answer as the previous server also had to verify
  the signatures. But if the section has come from rainspub then the server will get no answer or
  maybe a notification message (501 server not capable or maybe a new notification type. Should it
  even send? Because if the expiration time is chosen small enough it does not add much latency
  (assuming the reap function is also going through the server frequently). If we choose the
  expiration approach then we need to change the cache such that the reap function returns
  information what and where we have to send the delegation query). [I would prefer the explicit
  approach where rainspub sends a notification message back. Because it keeps the cache simple and
  it is easier to reason when an error occurs because it does not depend on multiple configurations]
  When the server receives the above mentioned notification message or if the query expired the
  server will send a new delegation query to a root rains server.

## Handle a missing public key
When a rains server receives a section it MUST verify all non expired signatures on it. In case the
server does not have the public key to verify the signature in the cache, it proceeds as follows:
1. Sends a delegation query to the server from which it has received the section. (Because the
   sending server also had to verify the signature it should still have the corresponding public
   key(s))
2. Adds the section together with the token used on the previously sent delegation query and the
   destination address to the pending signature cache. This step allows the handling goroutine to
   process another section and it does not have to wait until the answer arrives.

## Pending signature callback function
Depending on the answer the server receives as a response to the query it handles the pending
section differently. It first removes the token from the active token cache and sets the value of a
map which is keyed by the token to the number of assertions containing a delegation object. It then
checks if the sections are still valid. If that the case, it processes the section according to the
following cases where the token on the msg matches the one of the sent query:
- Assertion with one or several objects, containing the key(s):
  Option 1 is implemented
  1. Add all pending sections to the normal queue.
    \+ Use the same process, no special case, less complexity
    \- Slightly slower as the sections are not directly handled but added at the end of the queue.
       As the queue should mostly contain few elements, the added latency is expected to be small.
  2. Process all pending sections one after another by the current go routine.
    \- slow in case there are several sections waiting for the public key
  3. Create a new go routine for each pending section.
    \+ fast
    \- this approach would circumvent the maximum configured number of active go routines. It
       enables DOS attacks (resource exhaustion)
- Several assertions which have different needed public keys:
  After the assertion is added to the zoneKeyCache, decrease the map count and in
  case the count is 0 add all pending sections to the normal queue. (This makes sure that all public
  keys are in the cache when we handle the pending sections again. We assume that servers always
  respond with all delegations they have for a given zone.)
- Shard in range or zone containing a delegation assertion for the queried zone:
  After all sections have been added to the cache, add all pending sections to the normal queue.
- Shard in range or zone that do not contain a delegation assertion for the queried zone:
  This case should never happen. The previous server should not have been able to verify the
  signatures on this message as there exist no delegations to it.
- Notification Message: Action necessary at the following notification messages
  - 400	Bad message received: Resend query, update token in pending signature and active token cache.
  - 413	Message too large: Is impossible to happen on a single query. No further action is taken.
  - 500	Unspecified server error:
    1. Resend query, update token in pending signature and active token cache.
    2. Remove token from active Token cache and remove pending sections from the cache.
  - 501 Server not capable: Remove token from active Token cache and remove pending sections from
    the cache. Get another server?
  - 504 No assertion available: Remove token from active Token cache and remove pending sections
    from the cache.
- Assertion contains a redirect: Depending on the server's policy it either sends a redirect
   assertion back loaded from the assertion cache or starts the lookup itself.
   - Send redirect: Forward the received redirect assertion
   - Lookup itself: The server updates the token of the delegation cache, Adds the redirect
     assertion to the assertion and redirection cache and lookups up a redirect address in the
     redirection cache. (In the worst case it has to ask a root server)
