# Scalable signature updates, key rotation, and key rollover
RAINS deliberately does not have a revocation system as it would add complexity,
increase message overhead and latency to check the revocation state, and give
authorities a false perception of safety. Yes, it is easier to handle a key
compromise but it does not make it easy to detect one. Thus, to foster a secure
environment there should be a high enough cost in case of a key compromise or
falsely issued assertions to give authorities an incentive to have a well
protected public key infrastructure. The main mechanism of limiting an attacker
in case of compromise is the validity time of the signature on an assertion. In
this section we elaborate on different schemes that allow authorities to choose
short signature lifetimes while globally still having a scalable naming system.

## General remarks
- There is no revocation system. An assertion is valid until all its signatures
  are expired. 
- In this section when we talk about assertions, it also includes shards, zones
  and address assertions.
- The validity of an assertion is defined as the minimum expiration time along
  the signature chain to the root (i.e. the minimum of this assertion's
  expiration time and the expiration times of all direct delegation assertions
  to the root.) Be aware that the expiration time of an assertion is the maximum
  expiration time of all contained valid signatures. This can be larger than the
  assertion's validity time which also takes the expiration times of the
  delegation assertions into account. Thus, any assertion issued by an authority
  is at most as long valid as the assertion's validity delegating to it.
- Key rotation is a standard feature of RAINS and can be used frequently if
  necessary.

## Guidelines
- Assertions of an authority should not expire at the same time to avoid an
  incast scenario.
- An authority should be able to sign all its assertions within a quarter of the
  time from receiving the assertion delegating to it and the delegation's
  validity time. This allows the authority to sign in the first quarter all
  assertions to be valid until somewhere in the third quarter. At the start of
  the third quarter the authority should request a new delegation and repeat the
  above mentioned process with the renewed delegation.
- An assertion should be valid throughout a key roll over i.e. during a
  transition period the assertion will contain two signatures, one signed by the
  previous and one by the new private key.
- The validity of shards should be chosen small to allow for frequent changes
  e.g. one to several days. During the time a shard is valid no new assertion
  can be added by the authority.
- A RAINS server should store all received delegation assertions to quickly be
  able to calculate how long an assertion is valid and to proof the validity of
  an assertion.
- A RAINS server should answer a query with the longest valid assertion it has.
- A zone should negotiate with its superordinate zone a delegation renewal
  schedule. A zone can then request a new delegation according to the schedule
  or the superordinate zone pushes the delegations for the next period and the
  subordinate zone can start signing again.

## Tradeoffs
- Validity time of assertions: When the validity is longer, it puts less work on
  the authority but changes can only be made after the current assertion
  expires and in case of compromise it can be exploited for a longer period. 
- Signature lifetime: A short signature lifetime limits possible exploitations
  in case of a key compromise and it allows for frequent changes. On the other
  side, long signature lifetimes reduce network overhead from redistributing
  assertions and reduces the signing work of an authority.
- Number of key pairs: On the one hand having more key pairs increases the risk
  of a key compromise as a single signature is enough to get a valid assertion.
  On the other hand having an unused but still delegated key pair allows an
  authority to quickly switch to the unused pair in case of compromise of the
  main key pair.

## Ideal case
In an ideal setting an authority receives all delegation assertions on the
signature chain to the root in short regular intervals from its superordinate. A
short interval would be a couple of minutes which allows a possible attacker to
exploit a misconfiguration or a key compromise only for this short period. An
authority has two (or possibly more) key pairs already delegated to itself where
it only uses one key pair to sign its assertions. This way an authority can
quickly switch to a fresh key pair in case of key compromise. As the lifetime
of an assertion issued by the authority is upper bounded by the short lifetime
of the assertion delegating to it, it signs assertions on the fly with an even
shorter lifetime. This approach gives an authority great flexibility as its
assertions are only valid for a short period of time.

## Why we cannot use the ideal case
- Signing assertions on the fly is computationally or from a cost perspective
  too expensive for the amount of queries coming in. Due to the short lifetime
  of assertions caching is not or only in a very limited way possible.
- The delay would be too high as every query must be answered by the authority.
  This is especially sever when the authority is on a different continent or if
  the network is bad. As before, we cannot use caching to mitigate this problem.
  Instead an authority could have several active key pairs per region and serve
  customer from a local server. For each authority to maintain such a global
  infrastructure in a secure way is in today's setting too cost intensive.

## Mitigation
To reduce the amount of times an authority must sign signatures we have to
extend the lifetime of a signature. Due to the longer lifetime we can now deploy
caches throughout the network which can serve users locally and thus, greatly
reduce latency for cached assertions. It is still beneficial for a zone to
negotiate with its superordinate a delegation schedule to make sure that it can
sign all its assertions in time.

## Why having just one (active) key pair does not work
An authority might decide to work with just one key pair and when the renewed
delegation assertion from its superordinate zone arrives, resign all its
assertions. The problem here is, that the authority does not know if the sender
of a query already got the renewed delegation assertion or not. In case the
querier does not have the renewed assertion, it will not request one as the
previous one is still active and the validity time of the requested assertion
will be quite small. Additionally, all assertions from that zone will be
expiring at the same time when the previous delegation assertion expires and the
zone will likely be overwhelmed by a flood of incoming queries.

## Proposal: Two key pairs, key rotation, key rollover
With two key pairs, a zone will alternate between the two. The validity period
of both keys should be the same but they are in different phases. The phase of
the second key should start in the middle of the first key's phase. This way an
authority has the same amount of time to sign all its signatures independent of
the key phase as it is circular. This also maximizes the shortest amount of time
an authority gets to sign all its assertions.

An authority should as well agree with its superordinate on a delegation
assertion schedule. An assertion carries now always signatures from both key
phases (except at the beginning). Compared to the approach with just one key
pair, this time the querier does not have the delegation assertion for the
renewed key phase and must request it to be able to check the signature.

Also to avoid a massive amount of queries at the same time, an authority should
spread out the expiration time of all its assertions uniformly in the third
quarter of the lifetime of the assertion delegating to it. We chose the third
quarter so that in case of delay or technical problems an authority still has a
full (backup) quarter to sign all its assertions. It does not make sense to
resign assertions in the first and second quarter as there is not yet a new
delegation assertion available from the superordinate zone.

An authority is not bound to this policy and can shorten the lifetime of its
non-delegation assertions. A shorter lifetime results in more work for the
authority (to sign) and all servers caching assertions of this authority, higher
bandwidth utilization, and higher security by reducing possible exploitation
periods.

Key rollover is not a special case. Instead of renewing one of the key pairs, a
new key pair can be delegated by the superordinate zone (after a request from
the subordinate zone). The process of signing assertions is the same as if a key
pair would have been renewed, with the only difference that now the new key pair
instead of the renewed one is used.

|----|----|----|----| (0,5,10,15,20) Key1
          |----|----|----|----| (10,15,20,25,30) Key2

 |--------------| (1,16)
           |--------------| (11,26)
  |--------------| (2,17)
            |--------------| (12,27)
   |--------------| (3,18)
             |--------------| (13,28)