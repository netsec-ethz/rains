# General Design decisions
- Queries are answered as soon as any queried information is available, i.e. a server does not wait
  until it can completely answer a query but already responds with partial information.
- A server should keep all public keys necessary to validate the signatures on all its cached
  sections. This allows the server to answer all delegation queries about sections it has sent out.
- A server should respond to a delegation query with all matching public keys it believes the
  querier is missing to check a signature. A server does not keep state which delegations it has
  already sent to another server.
- After a configurable maximum number of delegation queries (e.g. 2) sent to the server from which
  this server received the message and not leading to all needed public keys, the server sends a
  delegation query to a predefined 'backup' server. If no 'backup' server is defined, the section
  will be dropped. Otherwise this server tries until the entry expires.
- A server should log all incoming messages and their content such that an external service can
  blacklist zones or IP addresses based on it and additional information.
- Pointers to delegation assertions are stored in the assertion cache to answer received delegation
  queries as well as in the zone key cache which is internally used to lookup public keys.
- It must be possible to update peer and zone blacklists at runtime such that an external service or
  coprocess analyzing rainsd's logging in real time can defend misbehavior and attacks (e.g. DoS)
- It must be possible to configure a server such that it does only iterative lookups for a specified
  list of addresses.
- It must be possible to configure a server to which other server address(es) it sends recursive
  queries. If there are several specified it chooses one according to a policy (random, round-robin,
  etc.)
- If no server address(es) is configured for iterative or recursive lookup, then the server just
  forwards redirect assertions back to the querier. In case the query was issued by the server
  itself it directly drops the redirect assertion (and in case of a delegation query, the section(s)
  waiting for the public key)

# Coalescing and/or splitting of incoming messages
- An answer to a query can arrive as a whole or in a fragmented way. Possible scenarios are:
  1. one message, one section
  2. one message, multiple section
  3. several messages, each with one section
  4. several messages with several section
  The server must be able to handle all these cases in a meaningful way. It should be possible to
  configure the server to react in different ways to them.

## Proposals
1. The server processes all incoming information directly and solely on a per section basis, i.e. if
   a message contains several sections it splits them up and handles each of them separately and in
   parallel. The number of simultaneously active goroutines is upper bounded. Assertions in response
   to a delegation queries can be configured to be handled with priority.
- Pending query cache designs:
  1. As soon as the server processes the first section which is an answer to a query it forwards the
     section and removes the entry from the pending query cache. (Disadvantages: If a server/client
     is interested in several information it should issue for each of them a separate query
     otherwise it might get always the same answer. Delegation must be handled as a special case)
  2. When an answer to a pending query arrives (either by token or by name, ctx and type) it is
     stored to the entry in the pending query cache and a configurable wait-time is set/reset after
     which all so far gathered sections are either sent back together as a response and the entry is
     removed from the pending query cache or if the server is allowed to do iterative lookup and the
     response is a delegation or a redirect send the query again to the new destination and update
     the token. (Disadvantage: complicated pending query cache)
  3. The entry in the pending query cache is only removed when expired. All answers arriving before
     the expiration are cached and then sent back to the sender. (Disadvantages: high delay and if
     the server decides to not cache a section then it can also not be used as an answer except if
     we would store each answering section to the pending query cache)
- Pending key cache:
  - A server can only resend a delegation query when the previous one has expired. This assures that
    a server does not get flooded with delegation queries after it rolled over a key.
  - The server checks if the token of an arriving section is stored in the cache and updates the
    cache accordingly. (In case the response is a redirect, iterative, recursive or no lookup. In
    case of negative proof remove sections and log it)
  - All arriving delegation assertions without a matching token are checked if they answers any of
    the sections in the pending key cache (hashmap lookup by zone, context, algorithm type and phase
    ID). All answered sections are added to the processing queue.
  - If the token on a message matches one in the pending key cache then the sections of this message
    are handled with priority (if not disabled in configuration).
  - There is a hashmap in the cache which is keyed by the token and the value is an object
    containing an expiration time and a pointer to an object containing all sections waiting for a
    public key. An entry is only removed from this hashmap if it has expired (a reap function takes
    care of this). This ensures that all messages in response to a delegation query are handled with
    priority.
  - Active Token cache is now part of the pending key cache because it is necessary to have a
    pointer from the token to the pending sections to remove them without raising an alarm in case
    the other server has sent a notification in response to the delegation query.
  - The server must log every section that gets dropped together with the destination which failed
    to send a delegation assertion in time.


2. The server processes incoming information on a per message basis, i.e. for each incoming message
   a goroutine is created (referred to as message goroutine in the reminder of this section) which
   is responsible for the appropriate handling of the message and its content as well as answering
   matching entries in the pending caches. The number of concurrently active message goroutines is
   restricted to a configurable amount (message goroutine counter). To account for case 3 and 4, the
   server coalesces messages with the same token if messages following the first one arrive within a
   configurable deadline (e.g. 10ms). This deadline is reset each time a message with the same token
   arrives. This is a tradeoff between sending directly partial (or complete in case 1 and 2)
   information with small delay and having more delay but be able to send mostly complete answers. A
   message goroutine works as follows:
   1. It removes the token from the active token cache.
   2. It creates for each contained section a new goroutine (referred to as section goroutine in the
      reminder of this section) which processes the section.
   3. Depending on a server configuration it performs one of the following steps:
    - It waits until all section goroutines are terminated. It then checks if the token is stored in
      one of the pending caches and invokes the waiting goroutines over a shared channel. (In this
      setting it would need considerable more complexity to also allow sections not intended as an
      answer to a query to be use as the answer)
    - It directly forwards the message to all pending queries or waits until the
      first section is done to invoke the goroutines waiting for a public key. (It is faster but the
      signatures on the message are not checked which I think is bad).
    - Some behavior in between the above 2 according to some policy (Disadvantage: added complexity)

   It is possible to forward the message without caching the sections. To avoid a deadlock of the
   system (e.g. when the maximum number of message goroutines are all waiting for a delegation
   assertion to arrive but it cannot be handled at its arrival because no message goroutine is free
   to process it) a section goroutine signals the message goroutine over a channel in case it has to
   wait such that the message goroutine counter can be decreased. Section goroutines maintain two
   channels to the message goroutine, one to signal back when it is done and the other to signal
   back when it has to wait for an answer. In case a section goroutine has to wait for a query's
   response, it adds a channel to the appropriate pending cache and blocks on it. When an answer
   arrived the pending cache signals the goroutine that it can continue its processing. Responses
   to delegations can be configured to be processes with high priority.

##Conclusion

I prefer the first proposal as sections are independent of each other and it leverages this
property. Goroutines do not have to communicate with each other and it is easier to add server
specific configurations because of that. The coalescing of information is in the pending query cache
by section instead of in the server's engine by message. In both approaches it is not necessary to
cache an answer to be able to respond to pending queries.

# Signatures

## Basic facts
- A signature is valid from the validSince to the validUntil time specified in the signature meta
  data. The validity time of a signature is further restricted by the validity period of the public
  key's delegation assertion, where the public key corresponds to the private key used to generate
  this signature.
- If there is no revocation mechanism then adding multiple signatures to a section does not increase
  security (because one signature is sufficient for a section to be accepted. Although it might be
  suspicious depending on the setting).
- With a revocation mechanism, an authority can add to each section k simultaneously valid
  signatures. A section can be used without being reissued as long as there are not all k private
  keys compromised used to sign this section. The overhead of validating such a section increases
  linear with the number of signatures.

## Signature design decisions
- Based on the signature meta data, it must be clear which public key was used to sign a section.
  This is required because we drop the whole section if not all non-expired signatures on and within
  a section are correct. Thus, it might be possible that the section is not dropped although it
  contains an incorrect expired signature (Having two different keys valid for the same algorithm in
  the same key phase is an inconsistency)
- Expired signatures are not checked because the public key might not be available anymore (it is
  also more efficient).
- If all signatures on a section are expired we do not cache it or use it to answer queries.

## Current state
- There is no specific revocation mechanism. Revocation is implicitly done via the validation period
  of the added signature by the authority.

## Simultaneous valid public keys proposals:
1. If we require that there is at most one public key valid at the same point in time we can fulfill
   the two requirements. In case the section is valid during a key rollover then the authority must
   add two signatures signed by different private keys such that publicKey1.validUntil + epsilon =
   publicKey2.validSince. Otherwise one signature is sufficient. The signature meta data consists of
   subjectZone, context, validSince, validUntil and signature algorithm type.
2. If we allow multiple public keys to be valid at the same point in time per subjectZone, context,
   and signature algorithm type then we need to add an additional identifier to delegation
   assertions and to the signature such that we know which private key was used to create the
   signature on the section. It is not possible to use the public key with e.g. the latest
   expiration time because there are no guarantees to which of the published public keys are in the
   cache of another RAINS server.

## Key rollover strategy
- It is sufficient for an authority to have two key pairs to provide contiguous validity of
  sections. The validity periods of the key pairs are alternating. After the currently valid (first)
  key expires, the authority can send a nextKey request to its super ordinate zone which can then
  issue a new delegation assertion for the first key before the second key expires. This process can
  then be repeated. This way the authority has always at least one valid key to sign sections.

## Conclusion
The second proposal is a generalization of the first proposal (i.e. that the second proposal can be
used by an authority as the first one but also gives more freedom to abuse it). The second proposal
enables to support future improvements with minimal effort. The second proposal is more complex to
implement but it is also harder to create an implementation that only works most of the times. The
first proposal divides the time into normal phases and key rollover phases while the the second
proposal is always in a key rollover phase. Thus, a lazy implementer might be tempted to ignore the
key rollover phase in proposal one as it is a special case which only occurs during a short amount
of time. We want to avoid this scenario. To mitigate the impact of authorities abusing the less
restricted proposal two, there needs to be a mechanism that analyses the amount of signatures an
authority adds to each section and depending on a policy blacklists it. (If there is a revocation
mechanism in place, an authority has an incentive to add more signatures to a section which then
influences the performance of the overall system negatively).The second proposal adds more
performance overhead because more signatures must be verified. Adding a revocation mechanism must be
well considered as then it is less important for an authority to really keep a private key safe, as
there is a backup. Also it is not really clear how an authority can discover a key compromise in a
timely fashion and then issue a revocation which also takes some time to spread over the network. If
we want to make sure that an authority really cares about keeping its private keys safe then not
having a revocation mechanism might be better. It also gives an incentive to authorities to choose a
short validity live time for public keys such that a compromised key can only be used in a short
amount of time. Additionally, it has a positive performance impact as less signatures are used per
section.