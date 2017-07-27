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
-

