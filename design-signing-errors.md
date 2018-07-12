# Signing error scenarios and handling

A zone operator is responsible that only valid and correct assertions are signed
and that they are published before the current ones will expire. An operator is
expected to be ready for most kind of errors and has a clear idea of what else
might go wrong even though it is highly unlikely. Especially when most of the
assertions are delegations and the zone guarantees a high up time to its
subzones. In this document we state different kind of errors, divide them by
severity and make some suggestions how a zone operator might handle them. To
avoid being totally cut off from the Internet in a catastrophic scenario, an
operator might be willing to sacrifice some security. We demonstrate where the
security boundary is below which the whole system would break down.

## Error classes

In practice there are many reasons for a machine to go down or losing connection
such as misconfiguration, hardware failure, natural disaster, unplugged cable,
DDoS attacks, etc. These error conditions can be abstracted into the following
error classes with increasing severity.

1. Authoritative servers become unavailable
2. A zone is unable to sign new assertions
3. A zone is unable to sign new assertions and the authoritative servers become
   unavailable
4. Private key compromise

We also have to differentiate between the cases where a zone further delegates
and a leaf zone. In the former case all subzones are also affected and the
damage is more severe. A zone must prepare both scenarios, one where the error
is caused within and one where the delegation chain is broken due to some other
zone further up the chain.

## System behavior during delegation failure

When a zone fails to issue a new delegation assertion before the current
delegation assertion will expire a delegation failure occurs. The consequences
are that all assertions of all zones in the tree of subordinates starting from
this zone will expire and the lifetime of new assertions will be zero (as it is
the minimum over all lifetimes along the delegation chain). This results in all
standard name lookups for these zones to fail. The only way for a client to
still obtain naming information is by doing a recursive lookup by himself and
accepting expired assertions. However, this puts much more pressure on the
authoritative server infrastructure of the affected zones as their assertions
will not be cached and all name lookups are recursive. Additionally, the zone
must make sure that the expired assertions are not removed from its
authoritative servers to still allow recursive lookup.

## Security considerations

A zone should follow the following security recommendations if it does not want
to become an easy target for an attacker.

- A rains server should directly drop all incoming expired assertions. Otherwise
  an adversary could just collect old assertions and push them to caching
  servers which then have the overhead of processing these messages and it
  degrades the quality of their cache.
- It should not be easy for a former owner of a name to claim that the
  delegation chain is broken and thus, by using his former valid but expired
  delegation and assertion to lead an unsuspecting user away from the new
  owner's site. This will not happen during a recursive lookup as long as all
  zones on the delegation chain are honest (which can be expected in most
  cases). But an adversary could present all the information directly to the
  user which then has to decide if it trusts the expired entries as it could as
  well be error class 3 where it might be the only way for a zone to not be
  totally unavailable.

## Handle error class 1

- Having more and location diverse servers
- Have a small fraction of the servers in the cloud and increase them in case of
  emergency. Obviously, this is more expensive.
- If connection to the cloud is lost, transport signed assertions stored on a
  hard drive to a place where connection is possible

## Handle error class 2

### Leaf zone

When a leaf zone is not able to sign assertions it affects only its own records.
Until the signing system is working again, it could respond to queries without
query option 5 set (accepting expired assertions) with a notification message
telling the querier that it has signing issues and can only respond with
assertions expired after time x. It is then up to the client if it wants to
resend the query and accept an assertion which expired after point x or if the
assertion expired too far back in time. This can be realized similar to the
scenario where a user wants to access a website with an invalid certificate
where the font color would depend on the time when the assertion expired. The
zone must also make sure that the authoritative servers do not remove expired
assertions from the cache until the problem is solved. Note that during
disruption other rains servers will not cache this zone's assertions and all
queries will be resolved recursively and thus, the authoritative servers will
experience higher load.

### Non-leaf zone

This case is more complex as other zones are affected by the outage as well.
Additionally to the issues described in the previous section the zone also has
to deal with the consequences of breaking the delegation chain. All assertions
issues by the subzones will not be cached as the lifetime of the assertion is
determined by the minimum expiration time along the delegation chain (which is
in the past).

It is also not possible to proof to another zone that this zone has signing
issues by means of a signature as it cannot sign it. A zone could technically
pre-sign a statement that it is unable to sign but it has to store this
statement somewhere and make sure that is does not fall into the wrong hands.
An adversary with such a statement could trick unsuspecting clients into
accepting assertions which have been revoked (by expiration) or to accept any
information in case the adversary also managed to compromise the signing key. It
is extremely hard to detect such an attack if the adversary is cautious and uses
these entries rarely at specific high profile targets.

To prevent the delegation chain to break, the error zone could ask its
superordinate zone to take over the signing of delegations. The error zone must
provide the superordinate zone with the names to sign. Let us look at an example
where ethz.ch's signing infrastructure goes down. It could then ask the ch zone
to directly delegate to the zone inf.ethz.ch. Instead of having two delegations
(:A: ch . ethz :deleg: ... and :A: ethz.ch . inf :deleg: ...) there would be
just one delegation skipping ethz (:A: ch . inf.ethz :deleg: ...). This will
obviously come at a (high) cost for the error zone. This approach will probably
fail for top level domains as the root zones are designed to handle large loads
on their authoritative servers but less on the signing infrastructure.

## Handle error class 3

### Leaf zone

The zone will be disconnected from the Internet until the signing and server
infrastructure is working again.

### Non-leaf zone

The zone will be disconnected from the Internet until the signing and server
infrastructure is working again. Additionally, it should ask its superordinate
zone to sign the delegation assertions for its subordinates as in error class 2.

## Handle error class 4

It is not necessary to distinguish between leaf and non-leaf zone as an
adversary having access to the signing key can create a delegation assertion.
Once an authority detects a private key compromise it can create a new key pair
and switch to it in the next delegation phase. The hard part about this error
class is detecting a key compromise, especially when an attacker is cautiously
using the key. Until the current delegation expires there is nothing a zone can
do to mitigate an adversary exploiting the private signing key.

## Attacks claiming a broken delegation chain

- When the contract between a zone's authority and its superordinate expires or
  is revoked, then the superordinate will not sign new delegations for this zone
  and it may delegate the namespace to a different authority. The zone could
  pretend in such a case that it lost connection with its superordinate and a
  client should accept expired assertions.
- When an adversary was able to obtain a signing key of a zone and got
  discovered it can still use the previously issued assertions by again claiming
  a lost connection to the zone's superordinate.
- An attacker might try to provide a user with a public key and then trick him
  to accept an assertion with a valid signature using the previously provided
  public key without looking at the delegation chain at all. A typical user does
  not know how the naming system with its root of trust works and might even
  accept an assertion without a signature at all if the browser does not warn
  him. He might even proceed after obtaining a warning similar to the case with
  invalid ssl certificates.

## Defenses

- Replicate infrastructure (also geographically)
- Large enough caches and rate limiting
- Store private key in a safe and tamper-proof way
- Have some infrastructure in the cloud to adapt quickly to changes in the load
  or local errors
- Have emergency plans

## Defenses using SCION

- Compared to the current state of DNSSEC where there is only one root and if it
  gets compromised or goes down the whole Internet cannot do name resolution in
  SCION there is one root per ISD. In a normal case a client is part of at least
  two ISDs. Thus, when all but one connected roots are inaccessible the client
  can still do name resolution. But on the other hand the set of trustable third
  parties increases with each ISD the client connects to.
- SIBRA to defend against some DDoS attacks
- PISCES to defend against some DDoS attacks
- DDoS filtering service in front of RAINS server (per AS max sending rate,
  history based) [Benjamin Rothenberger] to defend against some DDoS attacks

## Distinguish between outage and breach (key compromise)

As long as a key compromise is not detected every user of the system cannot
distinguish between a signature issued by the zone or by an adversary except the
zone itself. If a RAINS operator does not know someone trustworthy in a zone he
will treat an outage the same way independent of the cause (misconfiguration,
nature, malicious, etc.) as he cannot verify it. Thus, adding a 'reduced
security mode' in case a zone experiences an outage will probably do more harm
as a zone operator has less incentive to keep its private key(s) safe and having
a robust signing and serving infrastructure. Additionally, an unverifiable
'reduced security mode' gives an adversary more options how to exploit the
system.
