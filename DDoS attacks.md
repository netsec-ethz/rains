# DDoS attacks on RAINS

In this section we analyze the security of RAINS by looking at different kind
of attacker models. We demonstrate several attacks against a RAINS server or the
networking infrastructure. For each of these attacks we suggest possible defense
mechanism which an operator of rains servers can deploy to protect against them.
Some of the defenses are generally applicable and some require additional
features provided by next generation networks such as SCION. We are only
discussing attacks where the computational power of the attacker and the
defender are similar (linear). Once an attacker is exponentially stronger than a
defender he can just overwhelm the defender's resources with his sheer power
(computational and monetary wise). We are not considering passive attackers in
this section as they cannot interrupt the naming service just by observing the
network (privacy is part of another section).

## Attacker model 1

- Can send queries
- Cannot break cryptography
- Does not have authority over a zone
- Can have access to many different devices
- Has knowledge about the topology of the network

### RAM and cache exhaustion attacks

Attack 1: An adversary can send lots of assertions with invalid signatures. The
server has to parse all of them and they start filling up the input queue where
they are cached before one of the server's go routines is ready to process them.
Once the input queue is full, new arriving valid and invalid assertions are
getting dropped.

Defense: A server could have a policy that it never accepts assertions which are
not a response to a query issued by it. In case the server has authority over a
zone it only accepts assertions pushed from the local rainspub. This policy is
quite conservative and restricts the rains protocol substantially.

Another approach would be to have a monitoring service working on the server's
log files. As soon as the server has received more assertions with invalid
signatures from a single connection than a pre-configured threshold, the
monitoring service will blacklist the IP address of the malicious connection.

Attack 5: An attacker with many devices (e.g. IoT devices which are able to
create a TCP connection) can start from each of these devices simultaneously one
or multiple TCP connections to one RAINS server. Firstly, it takes more time for
connecting devices to establish a TCP connection and secondly, it fills up the
connection cache which will start to evict connections (possibly active once
e.g. when a recursive lookup is performed and the query is in the pending cache)
from the cache according to its LRU strategy.

Defense: None?

### CPU exhaustion attack

Attack 10: For each query the server has to split the name into subject name and
zone. An adversary can construct a name such that this computation will become
expensive. This is the case when the subject name contains many dots. An
attacker can generate many computational expensive queries and send them
together to a server.

Defense: A server can set a threshold on how many dots a query name can have
such that it still processes it. A monitoring service does not really help as
these queries probably come from many different connections which together are
expensive but blacklisting a client for one bad query is too much in my opinion.

## Attacker model 2

- Same capabilities as attacker model 1
- Can sign valid assertions for a zone either by having authority over this zone or being able to
  steal the private key from this zone's authority.

### RAM and cache exhaustion attacks

Attack 2: An attacker can create a domain, issue long-validity shards with a
wide shard range and push them to caching servers. Instead of pushing the
shards, the attacker can as well send a queries for a non-existent names in this
domain to the caching servers which then fetch the shards. In regular intervals
the attacker has to resend these queries to prevent the caching servers to evict
these large entries in case they use a lru policy.

Defense: The validity of an assertion or shard is at most as long as the
shortest validity along the delegation chain from the zone to the root. The
further away a zone is from the root the harder and more unlikely it is to get a
long-validity assertion as it has to obtain long-validity delegation from all
zones on the way to the root. Zones close to the root (such as TLDs) earn their
money mostly by delegating parts of their namespace and have an incentive that
their customers are continuously reachable through RAINS. Thus, they will likely
choose reasonable assertion expiration times. A caching server can as well be
configured to evict entries in its cache after a certain amount of time
independent of the entry's expiration time. This does not help against an
adversary who periodically requests large entries. The hard part here is to
distinguish between legitimate and adversarial queries. A caching server could
use a log monitoring service which raises an alarm in case it detects periodic
queries for large entries which can then be inspected by a human.

Attack 3: Same as attack 1 but the adversary firstly obtains a zone and a
delegation to it. Secondly, he starts creating a huge amount of assertions with
valid signatures and pushes them to a caching server. This time, not only the
input queue is filling up, but also the assertion cache.

Defense: The main problem here is to distinguish between a large valid zone
pushing its assertions and an attack scenario. A monitoring service can
calculate for each zone the ratio between received queries and received
assertions. If there are much more non-delegation assertions than queries it is
likely an attack and the corresponding zone can be blacklisted. This defense
does not help when the attacker is also sending queries for his zone or when the
assertions are mostly of delegation type. These scenario cannot or only with a
huge effort be defended as they imitate common patterns of a naming system. The
first one is the common case and in the second one the attacker's zone pretends
to be like zones near the root which are almost delegation only.

Attack 4: An attacker with the authority over a zone can create lots of dummy
delegation assertions with valid signatures. He would then push them to a RAINS
server to exhaust the delegation assertion cache where under normal
circumstances entries are only evicted after they have been expired as the
server must be able to produce a proof of all entries in its cache. The
consequences are severe in case this attack is successful as the server might
not be able to store all necessary delegations and thus, cannot check signatures
of newly incoming assertions which in turn would fill up the pending query cache
(waiting for the delegation assertion to arrive).

Defense: Having a monitoring service which counts the number of received
delegations per zone in a configurable time interval. In case the amount of
received delegations exceed a threshold and the zone is unknown i.e. it is not a
valid zone known for having many delegations like the root and TLDs and thus, is
part of a whitelist, the zone will be blacklisted. The problem here is that
since the attacker has authority over a zone, he can delegate to a number of
sub-zones such that the threshold is not reached and then repeat this step in
each of the sub-zones. This results also in a large amount of delegations
without being blacklisted. To restrict this defense evasion method the
monitoring system can raise an alert or blacklist zones which are more than a
configurable amount of steps away from the root.

Attack 6: An attacker having authority over a zone can send lots of queries with
a high valid until value about that zone to a RAINS server which has not yet
cached any of the answers. On receiving such a query it will put the query into
the pending query cache and forwards the query after a recursive lookup to an
authoritative server. The authoritative server under the control of the attacker
however will not respond to the sent query and lets it time out. The queried
server will retry several times without success while the original queries are
filling up the pending query cache. Once the cache overflows good and malicious
entries will be evicted according to a LRU policy.

Defense: A server can reduce the valid until value according to its policy. A
monitoring service might detect unusual queries and blacklist the IP address of
the connection from which it received those. In this case it would be receiving
many queries from the same connection in a short period of time with a large or
without i.e. infinite valid until value. This approach can also lead to false
positives e.g. when a large company internally deploys a naming service which
does all the lookups without a valid until time.

Attack 7: Similar to attack 6 but this time the target is the pending delegation
cache. The adversary has to be careful that it does not get blacklisted by the
queried server in case the authoritative server of his zone does not or only
after several retries respond to the delegation queries.

Defense: Only respond to delegation queries which are already cached, issued by
this server or are part of the delegation chain to the root. A server should not
be blacklisted if it does not respond to a random delegation query as it is not
responsible to answer it. The client should do a recursive lookup in which case
it should get an answer according to the above policy. If there is an assertion
in the cache of this server than the corresponding delegations are also in the
cache and it can prove the assertion's validity. In case an adversary sends a
non-delegation query to this server to force it to obtain the delegation, we are
in the attack 6 case and the corresponding defenses apply.

Attack 8: [From the draft] An attacker can cause traffic overload at a targeted
intermediate or authority service by crafting queries and sending them via
multiple query services. There is no amplification here, but a concentration,
with indirection that makes tracing difficult

Defense: ?

### CPU exhaustion attack 

Attack 9: An adversary with the authority over a zone can create many shards
with a large range which are all overlapping (E.g. an alphabetic equivalence to
numeric intervals like 1-101,2-102,...,100-200). On receiving a shard, the RAINS
server will perform a consistency check. In this case it has to compare the new
shard with all already cached shards and make sure that the new contained
assertions are also present in all the corresponding and already cached shards.
In this adversarial setting consistency checks are computationally expensive and
the server will probably not be able to check all incoming assertions and shards
which allows an adversary to inject inconsistent information.

Defense: A server would only check consistency while it has enough computing
power to maintain the regular service. Additionally, a monitoring system can
count the ratio of shards to assertions and blacklist zones which have a high
shard ratio. The counting is not trivial and might not be worth the effort to do
it online. The server could send an alarm in case it reaches its computational
capabilities and only the logs are inspected and searched for anomalies.

Attack 11: An attacker having authority over a zone can create a message
containing a zone with a huge amount of unsigned dummy assertions and send it
repeatedly to the same RAINS server. Each time the server has to perform an
expensive consistency check. Additionally, because the server cannot cache the
assertions (they are not signed) it always has to respond to a query with the
whole zone. This is wasting network capacity and time on the server and client
side (reading or writing a large message from the network).

Defense: A monitoring service can observe the frequency in which messages
containing a zone for each zone are received and blacklist the zones for which
it is higher than a specified threshold. Additionally, it can mark zones with
unsigned content as potentially malicious and count how many times a query is
answered with a zone. After a certain amount of such answers the operator of the
server might contact the authorities of such a zone and ask them to publish
shorter shards as well.

### Network exhaustion attack

Attack 12: An attacker having authority over a zone can push a message containing
a large zone to his target rains server (it is not necessary to sign the
contained assertions). The attacker then issues many queries for a non-existent
name of this zone to the target server. As the target server does not have
signed shards, it has to reply with the large zone file. This attack will use up
a large fraction of the server's network capabilities. TODO make some
calculation how many queries are necessary to saturate server components.

Defense: A monitoring service can mark zones with unsigned content as
potentially malicious and count how many times a query is answered with a zone.
After a certain amount of such answers the operator of the server might
blacklist the zone or contact the authorities of such a zone and ask them to
publish shorter shards as well. As an alternative, A server could decide to
never answers with a zone.

Attack 13: This attack is similar to Attack 1 but the target is not the server
but a specific link in the network. The attacker must have access to many
devices on one side of the target link. He then starts sending queries (which
again are returning a zone) from all these devices to several RAINS server on
the other side of the target link. In today's Internet the attacker cannot be
certain where the packets are passing through the network but most are
predictable [source? e.g. using traceroute].

Defense: Use the same defenses as in attack 1. Additionally, using SIBRA it is
not possible for an attacker to saturate the whole link.