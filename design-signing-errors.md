# Signing error scenarios and handling

A zone operator is responsible that only valid and correct assertions are signed
and that they are published before the current ones will expire. An operator is
expected to be ready for most kind of errors and has a clear idea of what else
might go wrong even though it is highly unlikely. In this document we state
different kind of errors, divide them by severity and make some suggestions how
a zone operator might handle them. To avoid being totally cut off from the
Internet in a catastrophic scenario, an operator might be willing to sacrifice
some security. We demonstrate where the security boundary is below which the
whole system would break down.

## Possible delegation errors

- Connection error between zone and its superordinate e.g. damaged networking
  cable, cable unplugged, machine shutdown, changed IP address, DDoS attack,
  natural disaster, etc.
- Signing hardware issues or failure of zone or any superordinate
- Connection between rainspub and its RAINS servers of zone or any superordinate
- Private key compromise of zone or any superordinate
- Delegation request by sending next-key assertion is not being answered
- Misconfiguration of rainspub or rains server of zone or any superordinate

## Error classes

The above mentioned error conditions can be abstracted into the following error
classes with increasing severity.

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

## Lower bound on security

- caching server only caches unexpired entries.

## Handle error class 1

- Move server into the cloud.

## Handle error class 2

## Handle error class 3

## Handle error class 4

## System behavior during delegation failure

When a zone fails to issue a new delegation assertion before the current
delegation assertion will expire a delegation failure occurs. The consequences
are that all assertions of all zones in the tree of subordinates starting from
this zone will be expired and no new assertions can be issued i.e. all standard
name lookups for these zones will fail. In such a catastrophic event the
subordinates could go into a special 'reduced security mode' (similar to
proceeding when the certificate of a website has expired). In this mode they
inform the clients that no delegation has been issued to them and that if they
still want a query to be resolved they have to send it with query option 5 set
which states that the client is willing to accepts expired assertions. A zone
has to make sure that their servers only reap assertions from their caches when
they have expired before a configured time interval. This approach prevents a
total outage of name resolution for some zones during some amount of time.

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