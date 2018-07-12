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

## Lower bound on security

A zone should follow the following security recommendations if it does not want
to become an easy target for an attacker.

- A rains server should directly drop all incoming expired assertions. Otherwise
  an adversary could just collect old assertions and push them to caching
  servers which then have the overhead of processing these messages and it
  degrades the quality of their cache.

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

A possible ........

## Handle error class 3

### Leaf zone

The zone will be disconnected from the Internet until the signing and server
infrastructure is working again.

### Non-leaf zone

Superordinate can ask supersuperordinate to sign a direct delegation to all its
important zones. Does not scale for the root zone as it is designed to answer a
lot of queries but not really to sign many. of course this will be expensive
...

## Handle error class 4

A reduced security mode should not affect later owner of name. How to make that
sure?

## Reduced security mode

send notification that signing issue and that client has to tell it wants
expired results. -> recursive request. It will become more expensive for the
'bad' zone as there is no caching anymore.

## Exploiting the delegation failure outage prevention

When the contract between a zone's authority and its superordinate expires or
when it gets revoked, then the superordinate will not sign new delegations for
this zone and it may delegate the namespace to a different authority. The zone
could pretend in such a case that it lost connection with its superordinate and
go into 'reduced security mode'. A client should be able to distinguish between
these two cases such that she knows if it is safe to use expired assertions.
Additionally, if a private key compromise has happened, then assertions issued
by the adversary should be excluded from a reduced security mode.
Should a server by able to push an assertion without a valid delegation into a
new server, probably not because it goes against the whole idea of having
expiration times to be secure.

## Additional defenses using SCION

- Compared to the current state of DNSSEC where there is only one root and if it
  gets compromised or goes down the whole Internet cannot do name resolution in
  Scion there is one root per ISD. In a normal case a client is part of at least
  two ISDs. Thus, when all but one connected roots are inaccessible the client
  can still do name resolution. But on the other hand the set of trustable third
  parties increases with each ISD the client connects to.
- SIBRA to defend against some DDoS attacks, see above
- PISCES
- DDoS filtering service in front of RAINS server (per AS max sending rate,
  history based) [Benjamin Rothenberger]

  ## Open questions

- How to distinguish between outage, breach from a zone view
- How to distinguish between outage, breach, or revocation from a client view