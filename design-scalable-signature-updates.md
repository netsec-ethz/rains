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
- The validity of shards should be chosen small to allow for frequent changes
  e.g. one to several days. During the time a shard is valid no new assertion
  can be added by the authority.
- A RAINS server should store all received delegation assertions to quickly be
  able to calculate how long an assertion is valid and to proof the validity of
  an assertion.
- A RAINS server should answer a query with the longest valid assertion it has.
- A zone should negotiate with its superordinate zone a delegation renewal
  schedule. A zone sends its new public key through the next-key assertion to
  its superordinate zone and expects it to sign the new delegation assertion
  with the new key. A superordinate zone not able to sign the next delegation
  with the new public key will result a broken delegation chain and probably in
  a sla violation.

## Tradeoffs

- Signature lifetime: A short signature lifetime limits possible exploitations
  in case of a key compromise and it allows for frequent changes. On the other
  side, long signature lifetimes reduce network overhead from redistributing
  assertions and reduces the signing work of an authority.
- Number of key pairs: On the one hand having more key pairs increases the risk
  of a key compromise as a single signature is enough to get a valid assertion.
  On the other hand having an unused but still delegated key pair allows an
  authority to quickly switch to the unused pair in case of compromise of the
  main key pair(s).
- Assuming only one signature per assertion: The longer the lifetime of an
  assertion is the longer the overlapping part with the next assertion is and
  the authority has more time to react to errors but period over which the
  assertions will be spread is shorter which results in more incoming traffic
  when the assertions are expiring.

## DNS case

In a DNS like setting an authority receives all delegation assertions on the
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
assertions. There are two problems here:

1. The authority does not know if the sender of a query already got the renewed
   delegation assertion or not. In case the querier does not have the renewed
   assertion, it will not request one as the previous one is still active and
   the validity time of the requested assertion will be quite small.
   Additionally, all assertions from that zone will be expiring at the same time
   when the previous delegation assertion expires and the zone will likely be
   overwhelmed by a flood of incoming queries.
2. Only having one key pair makes key rollover something special and people are
   nervous doing it as there is not an easy backup option. (See key rotation
   problem in DNSSEC where ICANN and Verisign worked for several years on a root
   key rollover plan and schedule but had to postpone it as a substantial amount
   of resolvers did not update their system to work with the new key [4]).

## Proposal: Two key pairs, key rotation, key rollover

With two key pairs, a zone will alternate between the two. The validity period
of both keys should be the same but they are in different phases. The phase of
the second key should start in the middle of the first key's phase. This way an
authority has the same amount of time to sign all its signatures independent of
the key phase as it is circular. This also maximizes the shortest amount of time
an authority gets to sign all its assertions.

An authority should as well agree with its superordinate on a delegation
assertion schedule to catch potential errors early and come up with a solution
before the delegation chain is interrupted.

Compared to the approach with just one key pair, a caching resolver either has
an unexpired delegation (and then it is the most recent one) and can use it to
calculate the lifetime of the assertion or the delegation is missing and it must
request it.

To avoid a massive amount of queries at the same time, an authority should
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
new key pair can be delegated by the superordinate zone (after it reeived a
next-key assertion from the subordinate zone). The process of signing assertions
is the same as if a key pair would have been renewed, with the only difference
that now the new key pair instead of the renewed one is used.

When a zone is delegating its namespace then the delegation assertion schedule
should take half the time of his superior. This way the zone has enough time to
cope with a possible delegation failure of its superior zone. Additionally, it
is more predictable for the subordinate zone which public key is used to sign
the delegation. A regular schedule helps to detect possible delegation errors
early on and gives the involved parties more time to solve them. Additionally,
it is the longest period for which one signature is sufficient for each
delegation assertion. This takes off pressure during signing for large zones
with many delegations and reduces the amount of work a rains server must do to
check the delegation's validity.

## Signing systems

There are several options how to build a signing system.

1. The easiest way is to store or generate the signing key on the same machine
   that is also used to sign and push the assertions to the authoritative
   servers. It is simple to maintain but also less challenging for an attacker
   to tamper with the system.
2. For highly important keys such a deployment is obviously not sufficient and
   much stricter rules on who, why, when, where and how can access the keys are
   necessary. As an example we can look at the DNSSEC root key which is
   redundantly stored at two secure facilities in the United States in hardware
   security modules (HSM) [6].
3. A simpler, cheaper, less efficient approach with similar security guarantees
   was proposed by Matsumoto et. al. [7] and improved in Fabian Murer's master
   thesis [8]. They are using commodity hardware in a observable touch-less
   environment.

## Benchmarking signing

The largest zone is '.com' with 134M registered domains. Next up is china's
'.cn' with 21.4M entries. Switzerland's '.ch' zone has a bit more than 2 Million
domains [5].

The benchmarks are run on a single machine using only one core with 2.9GHz. The
signing key and the assertions to sign are pre-loaded from files before the
measurements are stared. We want to determine the time it takes an authority to
sign a zonefile. We have several zonefiles containing entries similar in content
to what we expect a zone to have which vary in the number of entries. The
'Total' column states the amount of time it takes a zone to sign all assertions,
all shards and the zone.

| nofAssertions | assert/shard | Assertions [s] | Shards [s] | Zone [s] | Total [s] |
| -------------:|-------------:|---------------:|-----------:|---------:|----------:|
| 10000         | 10           | 0.6            | 0.08       | 0.1      | 0.78      |
| 10000         | 100          | 0.6            | 0.04       | 0.04     | 0.68      |
| 10000         | 1000         | 0.6            | 0.1        | 0.1      | 0.8       |
| 100000        | 10           | 6.3            | 1.1        | 14       | 21.4      |
| 100000        | 100          | 6.3            | 0.4        | 1.8      | 8.5       |
| 100000        | 1000         | 6.3            | 1.1        | 1.2      | 8.6       |
| 1000000       | 10           | 62             | 11.4       | >600     | >673      |
| 1000000       | 100          | 62             | 6.7        | 125      | 193.7     |
| 1000000       | 1000         | 62             | 17         | 29.6     | 108.6     |

An authority might decide to not sign assertions but instead group a certain
amount of them together and then only sign the shard. The authoritative servers
then only respond with shards to queries. This approach reduces the signing work
for an authority but increases the number of bytes sent in response to a query
as a shard in most cases contains more information than requested by the query.
TODO CFE: make measurements!

| nofAssertions | assert/shard | Shards [s] | Zone [s] | Total [s] |
| -------------:|-------------:|-----------:|---------:|----------:|
| 10000         | 3            | 0.08       | 0.1      | 0.78      |
| 10000         | 5            | 0.04       | 0.04     | 0.68      |
| 10000         | 7            | 0.1        | 0.1      | 0.8       |
| 100000        | 3            | 1.1        | 14       | 21.4      |
| 100000        | 5            | 0.4        | 1.8      | 8.5       |
| 100000        | 7            | 1.1        | 1.2      | 8.6       |
| 1000000       | 3            | 11.4       | >600     | >673      |
| 1000000       | 5            | 6.7        | 125      | 193.7     |
| 1000000       | 7            | 17         | 29.6     | 108.6     |

An authority might also use a combination of the above two approaches. The
signing work depends on the ratio between the two approaches and can be
calculated based on the above benchmarks.

TODO CFE create a benchmark which uses all the cores to determine go routine and
runtime overhead which is expected to be negligible as there is no locking
involved. But there might be some caching 'issues'.

## Cost of cloud instances for signing

Source: https://cloud.google.com/products/calculator/ (22.06.18)
Google: 8 cores, 8GB RAM, 375GB storage, US-central: 124$/month
Google: 8 cores, 8GB RAM, 375GB storage, Frankfurt: 157$/month

Source: https://calculator.s3.amazonaws.com/index.html
AWS: c3.2xlarge 8 vCPU, 15GB RAM, 160GB SSD, I/O high, US-east Virginia: 114$/month
AWS: c3.2xlarge 8 vCPU, 15GB RAM, 160GB SSD, I/O high, Frankfurt: 162$/month

## Bootstrapping

Every rains server must have a delegation assertion from the root (which is
self-signed by the root), a redirect assertion to know which name is responsible
to provide information about the root, a service assertion to obtain the name of
the root's naming service and port, and an ip4 assertion about the server's ip
address which hosts the root's naming service. With these four assertions a
rains server can do recursive lookup and obtain at the end of the process the
sought information or a proof that this information does not exist. Every
authority over a zone must create four such entries about its zone and let its
superordinate sign and store them. Example of the four necessary
bootstrap assertions for the root.

1. :A: @ . . :deleg: <public key>
2. :A: @ . . :redir: ns
3. :A: ns . . :srv: ns1 1234 0
4. :A: ns1 . . :ip4: 192.0.2.0

The third assertion is only necessary until there is a standard port for RAINS
(such as 53 is for DNS).

In SCION every ISD will have a root zone. A client obtains the root public
key(s) of its ISD through the TRC file which is the root of trust in a SCION
network.

## Sources

[1] THE DOMAIN NAME INDUSTRY BRIEF: https://www.verisign.com/assets/domain-name-report-Q12018.pdf
(22.06.18)
[2] various statistics on .ch domain names and DNS https://www.nic.ch/statistics/ (22.06.18)
[3] statistics about ch name servers https://securityblog.switch.ch/2018/03/20/a-day-in-the-life-of-nic-ch/
[4] Key rollover postponed https://www.icann.org/news/announcement-2017-09-27-en
[5] Number of domain names per TLD https://www.verisign.com/en_US/domain-names/dnib/index.xhtml?section=tlds
(11.07.18)
[6] DNSSEC root key information
https://www.cloudflare.com/dns/dnssec/root-signing-ceremony/ (11.07.18)
[7] CASTLE https://dl.acm.org/citation.cfm?id=2991115
[8] Fabian Murer's master thesis [TODO CFE get source]
