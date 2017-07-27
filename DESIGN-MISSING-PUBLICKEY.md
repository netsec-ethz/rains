# Handling of a missing public key
When a rains server receives a section it MUST verify all non expired signatures on it. In case the
server does not have the public key to verify the signature in the cache, it proceeds as follows:
1. Sends a delegation query to the server from which it has received the section. (Because the
   sending server also had to verify the signature it should still have the corresponding public
   key(s))
2. Adds the section together with the token used on the previously sent delegation query and the
   destination address to the pending signature cache. This step allows the handling go routine to
   process another section and it does not have to wait until the answer arrives.
3. Depending on the answer the server receives as a response to the query it handles the pending
   section differently. It first removes the token from the active token cache. It then checks if
   the sections are still valid. If that the case, it processes the section according to the
   following cases where the token on the msg matches the one of the sent query:
- Assertion with one or several objects, containing the key(s):
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
  Set the value of a map which is keyed by the token to the number of assertions containing a
  delegation object. After the assertion is added to the zoneKeyCache, decrease the map count and in
  case the count is 0 add all pending sections to the normal queue. (This makes sure that all public
  keys are in the cache when we handle the pending sections again. We assume that servers always
  respond with all delegations they have for a given zone.)
- Assertion(s) not all containing either a public key, an IP4, an IP6 or a redirect object for the
  queried zone will be logged and possibly blacklisted. We do not want to allow normal assertion(s)
  to take the path over the priority queue although they are not. (An assertion containing one of
  the four object types and several more is fine). The same applies for shards where the queried
  name is not in the shard range.
- Shard in range or zone containing a delegation assertion for the queried zone:
  After all sections have been added to the cache, add all pending sections to the normal queue.
- Shard in range or zone that do not contain a delegation assertion for the queried zone:
  This case should never happen. The previous server should not have been able to verify the
  signatures on this message as there exist no delegations to it.
- Signature(s) on one or several sections are incorrect:
  1. Remove all other delegation assertions from the zoneKeyCache. Remove all pending sections from
     the cache. Send a response back e.g. a notification?
  2. Remove all other delegation assertions from the zoneKeyCache. Resend the query and update the
     token on the pending signature cache.
- Notification Message:
  Depending on the notification type different behavior. Resend query, drop pending sections silent,
  send response to dropped pending sections
- Assertion containing one redirect and one or several IP4/IP6 objects for the redirect name:
  Send a delegation query to the redirected address
- Assertion containing one redirect but no IP4/IP6 object:
  1. If the server has a cached IP assertion for the redir name, send a delegation query to it, else
     send an IP4/IP6 query for the redirected name to a root server.
  2. If the server has a cached IP assertion for the redir name, send a delegation query to it, else
     send an IP4/IP6 query for the redirected name to the server from which it received the redirect
- Assertion contains several redirects or several assertions containing redirects
  Choose one redirect at random and do the same as above for one redirect.


## Design decisions
- The callback function for the pending sections is not triggered by delegation assertions which can
  be used to verify the signature but are not a response to the query issued for this information.
  The event that another server pushes such a delegation assertion exactly in the moment where this
  server is waiting for this delegation assertion is negligible. But we would have to check each
  incoming section if it matches any of the sections in the pending caches which incurs unnecessary
  overhead.
- We do not keep state how many times we issued a query for a given zone. We repeat it until the
  query expires (which is configurable). A malicious entity could send alternating redirects from
  two of its servers and without an expiration for the query the server would ask them infinitely.
- To be able to blacklist malicious servers which do not respond to delegation queries or with
  incorrect answers we log the connection information of them. An external service can then decide
  if a server or zone should be blacklisted. To make this approach work, a server should not start a
  lookup for another server but either directly respond with a cached result or send a redirect. (
  If the server which the second server uses for its lookup does not respond, then it seems for the
  first server that the second server is the malicious one and not the third one) However, if one
  has two or several rains servers, it is still possible to configure them such that only some of
  them are doing recursive lookup. Those servers doing recursive lookup must be white-listed in the
  local blacklisting service.

