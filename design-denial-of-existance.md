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

TODO CFE (how detailed?)

### Shard semantic

A section's validity start at the point of the earliest signature validSince
time and expires at the latest signature validUntil time. Note that there might
be a time interval in between where no signature is valid. A contained Assertion
is an assertion present within a shard. A shard is valid from t_sb to t_se and
without loss of generality an assertion from t_ab to t_ae within the range of
the shard. Note that contained assertions MAY have different validity times. A
shard contains a flag indicating if its purpose of denial of existence is valid
throughout the shard's validity or not. If the flag is set, the following
statement hold:

- During the validity of the shard, all assertions contained in the shard are
  valid and no other assertion in the shard's range is valid within this
  validity period.

In this setting an authority restricts itself to when it is allowed to make
changes to the shard ranges and thus, to which shard an assertion belongs to and
changes to an assertion's content. But on the positive side, it allows the
authority to have stronger guarantees about its namespace. As long as all shards
and assertions have the same expiration time, an authority can make changes to
its namespace at these expiration times. Expiring all entries at the same point
in time results in lots of queries at this time. This might not be feasible for
large zones. To allow assertions and shards to expire at different points in
time and still be able to change their content, the authority must make changes
to its shard ranges and shard contents alternatingly.

If the flag is not set, then the naming authority gets much more freedom when to
make changes to its namespace. Then the following statements hold true for a
shard.

- All assertions in range of the shard which are valid at t_sb MUST BE contained
  in the shard.
- Any contained assertion without a signature is valid from t_sb until t_se.
  Thus, no change is allowed to any contained assertion without a signature
  before t_se.
- Any contained assertion with a signature is valid until the assertion's
  signature expires. This allows to make changes to an assertion before the
  containing shard expires (removing the assertion or make changes to its
  content).
- A shard in response to a query asking for a name and type containing an
  assertion with that name and type with an expired signature means that
  probably no value for this name and type exist anymore ('probably' because the
  authoritative naming server might have fail to serve the updated name in time
  or the caching resolver has not issued a new query for that name and type and
  forwarded the correct response. This behavior can be detected by looking at
  the shard issued subsequently. Although there can be false positives close to
  the change time as the query can arrive before the change at the naming server
  but after the change at the client).
- A shard in response to a query asking for a name and type containing no
  assertion for that name and type means that probably no value for this name
  and type exist. The same reasoning for 'probably' above applies here too.

After time t_sb a shard is an approximation of which assertions are valid within
its range and validity time. The quality of the approximation depends on the
frequency and timing of changes within the shard range.

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

## Negative answer with Bloom filter

Instead of sending a zone or a shard as a proof of non existence, a naming
authority might as well send a signed bloom filter. A bloom filter either says
that an assertion might exist or it certainly does not. In case the bloom
filter's result is negative, a caching resolver can proof non existence with it.
Otherwise, it has to send a query to the naming server, which then responds with
an assertion, shard, zone or a different bloom filter which gives a negative
response. Depending on the probabilistic bounds of the bloom filter, a naming
authority can influence the load on its naming servers as the amount of negative
queries a caching resolver can directly handle depends on it. Large zones cannot
substitute a zone with a bloom filter as its size becomes to large. A naming
authority must tradeoff between a bloom filter's size and its accuracy.
E.g. If there is a bloom filter for each 1000 assertions and the false positive
rate is 1%, its size is 1.17KB. [https://hur.st/bloomfilter/]

However, in a more dynamic setup, where an authority is allowed to add and
remove assertions during the validity of a bloom filter, its results cannot be
totally trusted either and the probabilistic bounds do not hold anymore. In this
case, the caching resolver should forward all queries which have not a hit in
the assertion cache.

Another down side of bloom filters is that they do not contain assertions and
hence, cannot be used to directly serve an assertion. Som analysis of this
tradeoff would be useful.

## Internet scenario

## Cloud scenario

## Conclusion
