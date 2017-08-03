# General Design decisions
- Queries are answered as soon as any queried information is available, i.e. a server does not wait
  until it can fully answer a query but already responds with partial information.
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
  coprocess analyzing rainsd's logging in real time can defend DoS attacks.
- It must be possible to configure a server such that it does only iterative lookups for a specified
  list of addresses.
- It must be possible to configure a server to which other server address(es) it sends recursive
  queries. If there are several specified it chooses one according to a policy (random, round-robin,
  etc.)
- If no server address(es) is configured for iterative or recursive lookup, then the server just
  forwards redirect assertions back to the querier. In case the query was issued by the server
  itself it directly drops the redirect assertion (and in case of a delegation query, the section(s)
  waiting for the public key)

## Section and Message processing proposal
- The number of concurrently active goroutines working on messages are restricted to a configurable
  amount. To avoid a deadlock of the system (e.g. when the maximum number of message goroutines are
  all waiting for a delegation assertion to arrive but it cannot be handled at its arrival because
  no message goroutine is free to process it) a goroutine spawned to work an a contained section
  signals the message goroutine over a channel in case it has to wait such that the message
  goroutine counter can be decreased.
- Goroutines working on sections maintain two channels to the goroutine of the message, one to
  signal back when it is done and the other to signal back when it has to wait for an
  answer.
- In case a section goroutine has to wait for a query's response, it adds a channel to the
  appropriate pending cache and blocks on it. When an answer arrived the pending cache signals the
  goroutine that it can continue its processing.
- Message goroutines work as follows:
  1. The engine coalesces incoming response messages with the same token until some configurable
    wait-time has passed (e.g. 10ms). Each time a message with the same token arrives the countdown
    is reset to the configured wait-time. In case the incoming message is not a response to a query
    it goes straight to step 3.
  2. When the wait-time is over, the server removes the token from the active token cache.
  3. The message goroutine creates for each contained section(s) a new goroutine
  4. Depending on the configuration one of the following processing steps is performed.
    - The message goroutine waits until all sections are successfully processed. It then checks if
      the token is stored in one of the pending caches and invokes the waiting goroutines. At last,
      it decreases the message goroutine counter.
    - The message goroutine directly forwards the message to all pending queries or waits until the
      first section is done to invoke the goroutines waiting for a public key. Then it waits for all
      sections to terminate and decreases the message goroutine counter.
    - Some behavior in between the above 2 according to some policy

### Implementation proposal
- Message goroutines create a waitgroup to determine when all go routines are done.
- The active token cache must return if a token belongs to a delegation query response such that
  it is always directly processed.

## Signatures

### Basic facts
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

### Signature design decisions
- Based on the signature meta data, it must be clear which public key was used to sign a section.
  This is required because we drop the whole section if not all non-expired signatures on and within
  a section are correct. Thus, it might be possible that the section is not dropped although it
  contains an incorrect expired signature (Having two different keys valid for the same algorithm in
  the same key phase is an inconsistency)
- Expired signatures are not checked because the public key might not be available anymore (it is
  also more efficient).
- If all signatures on a section are expired we do not cache it or use it to answer queries.

### Current state
- There is no specific revocation mechanism. Revocation is implicitly done via the validation period
  of the added signature by the authority.

### Simultaneous valid public keys proposals:
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

### Key rollover strategy
- It is sufficient for an authority to have two key pairs to provide contiguous validity of
  sections. The validity periods of the key pairs are alternating. After the currently valid (first)
  key expires, the authority can send a nextKey request to its super ordinate zone which can then
  issue a new delegation assertion for the first key before the second key expires. This process can
  then be repeated. This way the authority has always at least one valid key to sign sections.

### Conclusion
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