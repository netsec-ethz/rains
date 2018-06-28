# Scalable Signature updates and key rotations

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

## DNS case

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

## Why we do not want to use the DNS case

- Signing assertions on the fly is computationally or from a cost perspective
  too expensive for the amount of queries coming in. Due to the short lifetime
  of assertions caching is not or only in a very limited way possible.
- The delay would be too high as every query must be answered by the authority.
  This is especially sever when the authority is on a different continent or if
  the network is bad. As before, we cannot use caching to mitigate this problem.
  Instead an authority could have several active key pairs per region and serve
  customers from a local server. For each authority to maintain such a global
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

When a zone is delegating its namespace then the delegation assertion schedule
should take half the time of his superior. This way the zone has enough time to
cope with a possible delegation failure of its superior zone. Additionally, it
enables this zone to also have a regular delegation assertion schedule with its
subordinate. A regular schedule helps to detect possible delegation errors early
on and gives the involved parties more time to solve them.

## Possible delegation errors

- Connection error between zone and its superordinate e.g. damaged networking
  cable, cable unplugged, machine shutdown, changed IP address, DDoS attack,
  natural disaster, etc.
- Signing hardware issues or failure of zone or any superordinate
- Connection between rainspub and its RAINS servers of zone or any superordinate
- Private key compromise of zone or any superordinate
- Delegation request by sending next-key assertion is not being answered
- Misconfiguration of rainspub or rains server of zone or any superordinate

## System behavior during delegation failure

When a zone fails to issue a new delegation assertion before the current
delegation assertion will expire a delegation failure occurs. The consequences
are that all assertions of all zones in the tree of subordinates starting from
this zone will be expired and no new assertions can be issued i.e. all standard
name lookups for these zones will fail. In such a catastrophic event the
subordinates could go into a special 'reduced security mode' (similar to
proceeding when the certificate of a website has expired). In this mode they
inform the clients that no delegation has been issued to them and that if they
still want a query to be resolved they have to send it with query option 9 set
which states that the client is willing to accepts expired assertions (TODO ADD
THIS QUERY OPTION TO THE RAINS DRAFT). A zone has to make sure that their
servers only reap assertions from their caches when they have expired before a
configured time interval. This approach prevents a total outage of name
resolution for some zones during some amount of time.

## Exploiting the delegation failure outage prevention

When the contract between a zone's authority and its superordinate expires or
when it gets revoked, then the superordinate will not sign new delegations for
this zone and it may delegate the namespace to a different authority. The zone
could pretend in such a case that it lost connection with its superordinate and
go into 'reduced security mode'. A client should be able to distinguish between
these two cases such that she knows if it is safe to use expired assertions.

## Additional defenses using SCION
- Compared to the current state of DNSSEC where there is only one root and if it
  gets compromised or goes down the whole Internet cannot do name resolution in
  Scion there is one root per ISD. In a normal case a client is part of at least
  two ISDs. Thus, when all but one connected roots are inaccessible the client
  can still do name resolution. But on the other hand the set of trustable third
  parties increases with each ISD the client connects to.
- SIBRA to defend against some DDoS attacks, see above

## Benchmarking signing

The largest zone is '.com' with 134M registered domains. Next comes china's '.cn' with 21.4M
entries. Switzerland's '.ch' zone has a bit more than 2 Million domains.

Signing is currently done with just one core on my machine with 2.9GHz.
We were using a benchmark to determine the time it takes an authority to sign a
zonefile. We have two zonefiles containing 100'000 and 1'000'000 entries similar
in content to what we expect a zone to have.

| nofAssertions | assert/shard | Assertions | Shards | Zone   | Total |
| -------------:|-------------:|-----------:|-------:|-------:|------:|
| 10000         | 10           | 0.6        | 0.08   | 0.1    | 0.78  |
| 10000         | 100          | 0.6        | 0.04   | 0.04   | 0.68  |
| 10000         | 1000         | 0.6        | 0.1    | 0.1    | 0.8   |
| 100000        | 10           | 6.3        | 1.1    | 14     | 21.4  |
| 100000        | 100          | 6.3        | 0.4    | 1.8    | 8.5   |
| 100000        | 1000         | 6.3        | 1.1    | 1.2    | 8.6   |
| 1000000       | 10           | 62         | 11.4   | >600   | >673  |
| 1000000       | 100          | 62         | 6.7    | 125    | 193.7 |
| 1000000       | 1000         | 62         | 17     | 29.6   | 108.6 |

## Cost of cloud instances for signing

Source: https://cloud.google.com/products/calculator/ (22.06.18)
Google: 8 cores, 8GB RAM, 375GB storage, US-central: 124$/month
Google: 8 cores, 8GB RAM, 375GB storage, Frankfurt: 157$/month

Source: https://calculator.s3.amazonaws.com/index.html
AWS: c3.2xlarge 8 vCPU, 15GB RAM, 160GB SSD, I/O high, US-east Virginia: 114$/month
AWS: c3.2xlarge 8 vCPU, 15GB RAM, 160GB SSD, I/O high, Frankfurt: 162$/month

## Open questions

- Is it possible to sign in parallel when the key is in a hardware module?
- How to distinguish between outage, breach from a zone view
- How to distinguish between outage, breach, or revocation from a client view

## Sources

[1] THE DOMAIN NAME INDUSTRY BRIEF: https://www.verisign.com/assets/domain-name-report-Q12018.pdf
(22.06.18)
[2] various statistics on .ch domain names and DNS https://www.nic.ch/statistics/ (22.06.18)
[3] statistics about ch name servers https://securityblog.switch.ch/2018/03/20/a-day-in-the-life-of-nic-ch/


|----|----|----|----| (0,5,10,15,20) Key1
          |----|----|----|----| (10,15,20,25,30) Key2

Non-delegation assertions
 |--------------| (1,16)
           |--------------| (11,26)
  |--------------| (2,17)
            |--------------| (12,27)
   |--------------| (3,18)
             |--------------| (13,28)