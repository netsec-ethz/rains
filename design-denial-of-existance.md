# Design Denial of Existence

In a secure public naming system, all entries must be authenticated by the
authority of the particular namespace. It is straight forward to sign an
existing name with a private key corresponding to a delegated public key. But
how do we handle negative responses as there is a infinite amount of
non-existing names.

## Tradeoffs

### Online vs offline signing

The least complex approach to proof non-existence of a name is by sending back a
signed negative assertion of the queried name and type. Drawbacks of this
approach are that negative assertions cannot be signed in advance, on demand use
of the private signing key and inefficient caching. As there is an infinite
amount of non-existing names a zone cannot pre sign all its negative assertions
which results in a higher per query computational cost. The load on naming
servers is also increased as most of the negative queries will be forwarded
because the probability that someone else requests the exact same non-existing
name from the same caching resolver before the entry is evicted or expired is
small. There are also some security concerns as the private signing key is used
on demand. E.g. it allows an attacker to use the naming server as a restricted
signing oracle. The benefit of offline signing is that it can be done in a more
secure physically separated facility and provide the newly signed sections once
before the current ones expire.

### Dynamic vs static system

In a static system, entries are valid for a specific amount of time determined
by the authority over that namespace. During this time no change is allowed to
happen in the namespace as they would otherwise conflict denial of existence
entries. While this system is much easier to reason about, there is high load
during transition and it is not suited for some use cases such as a cloud
setting. The flexibility an authority gets by using a dynamic system comes at a
higher complexity cost and weaker guarantees for denial of existence proofs.

### Internet vs Cloud setting

A cloud provider must be able to react quickly to changes in load of all the
different services running on its platform. This means spinning up new machines
and making them accessible within seconds. This also means that the naming
system must be able to publish changes within seconds. The advantage of a cloud
provider is that he has control over his naming servers and caching resolvers.
The naming servers can push new assertions (and if necessary also shards) to all
caching resolvers which then directly serve these assertions instead of the
previously cached shard. Because positive queries have stricter latency
requirements than negative once, caching resolvers should give preference to
positive answers which makes it sufficient for a naming server to just push new
assertions.

In the Internet a naming authority has no control over where entries about its
namespace are cached and for how long (besides an upper bound due to the
signature lifetime). Thus, pushing updated information is not an option. But it
can still provide the new assertions for newly incoming queries. Depending on
the lifetime of shards, it can tradeoff lower load on its naming servers to
obtain better user experience through faster changes. Here the problem is that a
caching resolver who has a cached denial of existence will not issue again a
query to the naming server until the entry expired.

## Background

DNSSEC originally used NSEC records to proof denial of existence of a name.
Because it is trivial to enumerate a zone with NSEC and some people consider
that as a threat, NSEC3 was introduced. In RAINS shards and zones are used to
proof non existence of a name. All three proposals proof non existence by
providing a range. The first two claim that there is no entry within the range
and the third one explicitly lists all existing entries within that range
rendering everything else non existent.

### NSEC

TODO CFE (how detailed?)

### NSEC3

TODO CFE (how detailed?)

### Shards and Zones

- new shard semantic

## Shards vs NSEC3

| What               | Shard                  | NSEC3               |
|--------------------|------------------------|---------------------|
| Payload            | medium - large         | small               |
| Range size         | flexible               | to next entry       |
| Signing time       | range dependent        | many small entries  |
| Pr[cache hit]      | range dependent        | is there some data? |
| Cache flexibility  | range dependent        | high                |
| :Q: response time  | log(n) (Interval tree) | ?                   |
| Zone enumeration   | trivial                | less-trivial        |
| Neg Proof about    | values&types per name  | types per name      |
| Use as Pos Proof   | yes                    | no                  |
| Offline signing    | yes                    | yes                 |

## Negative answer with probabilistic bounds

## Internet scenario

## Cloud scenario

## Conclusion
