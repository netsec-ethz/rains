# Signature verification, roll over, and validity

## Requirements for section signatures
- Based on the signature meta data, it must be clear which public key was used to sign a section.
  This is required because we drop the whole section if not all signatures on and within a section
  are correct. (We do not check expired signatures due to efficiency reasons. If all signatures on a
  section are expired we do not cache it or use it to answer queries. Thus, it might be possible
  that the section is not dropped although it contains an incorrect signature)
- It must be possible to have one or multiple key rollover(s) during the validity period of a
  section. Thus, it must be possible to store several public keys for the same context, subjectZone,
  signature algorithm tuple.

## Basic facts
- A signature is valid from the validSince to the validUntil time specified in the signature meta 
  data. The validity time of a signature is further restricted by the validity period of the public 
  key corresponding to the private key used to generate this signature. 
- If there is no revocation mechanism then adding multiple signatures to a section does not increase
  security (because one signature is sufficient for a section to be accepted. Although it might be
  suspicious depending on the setting).
- With a revocation mechanism, an authority can add to each section k simultaneously valid 
  signatures. A section can be used without being reissued as long as there are not all k private 
  keys compromised used to sign this section. The overhead of validating such a section increases 
  linear with the number of signatures.

## Current state
- There is no specific revocation mechanism. Revocation is implicitly done via the validation period
  of the added signature by the authority.

## Proposals
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

# Signature cache design and implementation

## zone key cache requirements for proposal 1
- cache has a fixed size which is configurable (to avoid memory exhaustion of the server in case of
  an attack)
- public keys issued by the authority of the zone running the server will only be removed from the
  cache when they are expired.
- all public keys from other zones are either removed because they are the least recently used in
  case the cache is full or are expired. 
- it must provide an insertion function.
- it must provide fast lookup of a zone key based on subjectZone and algorithm type and phase id. It
  only returns valid public keys.
- it must provide a mechanism to delete expired elements or in case the cache is full the least
  recently used public key.
- all cache operations must be safe for concurrent access


## zone key cache implementation
- lru strategy is implemented as a linked list where pointers to the head and tail of the list are
  accessible.
- on insertion or lookup of a key it is moved to the head of the list
- in case the cache is full the public key at the tail of the list is removed.
- to allow fast lookup a hash map is used. It is keyed by the tuple subjectZone, signature algorithm
  type, and phase identifier. The value is a pointer to the corresponding list node.
- a list node contains a set (safe for concurrent accesses) of public keys, the subjectZone and
  phase identifier for which these keys are used for. (the latter two are needed to remove the entry
  from the hashmap in case of removal) 

## extra key cache requirement and implementation
- similar to the zone key cache with the only difference that instead of the phase identifier, an
  extra key has a key space identifier.

## infrastructure key cache requirement and implementation
- depends on how infrastructure keys are used. This is not yet specified. 
