# DDoS attacks on RAINS

In this section we analyze the security of RAINS based on different kind of
attacker models. We demonstrate several attacks against a RAINS server or the
networking infrastructure. For each of these attacks we suggest possible defense
mechanism which an operator of RAINS servers can deploy to protect against them.
Some of the defenses are generally applicable and some require additional
features provided by next generation networks such as SCION. We are only
discussing attacks where the computational power of the attacker and the
defender are similar (linear). Once an attacker is exponentially stronger than a
defender he can just overwhelm the defender's resources with his sheer power
(computational and/or monetary wise). We are not considering passive attackers
in this section as they cannot interrupt the naming service just by observing
the network (privacy is part of another section).

## Attacker model 1

1. Has access to many different devices which are able to send queries
2. Cannot break cryptography
3. Does not have authority over a zone
4. Has knowledge about the topology of the network
5. Is similar in strength as the defender (linear)

### RAM and cache exhaustion attacks

Attack 1: An adversary can send lots of assertions with invalid signatures. The
server has to parse all of them and they start filling up the input queue where
they are cached before one of the server's go routines is ready to process them.
Once the input queue is full, new arriving valid and invalid assertions are
getting dropped.

Defense: The infrastructure should have enough capacity to not run into this
problem. There could be a rate limiting service in front of the servers which
divides traffic into buckets through a randomized hash function (the seed is
frequently changed) and starts dropping queries once a bucket used up its fair
share. This approach results in a reduced service but prevents a total outage.
An adversary which is capable of persistently filling up all the buckets is not
part of the attacker model (violates nr. 5).

A caching resolver could have a policy that it never accepts assertions which
are not a response to a query issued by it. This approach does not add
additional state as the server has to keep the token anyway and looking up a
token is a fast operation.

An additional measure would be to have a monitoring service working on the
server's log files. As soon as the server has received more assertions with
invalid signatures from a single connection than a pre-configured threshold, the
monitoring service will blacklist the IP address of the malicious connection.

Attack 2: An attacker with many devices (e.g. IoT devices which are able to
create a TCP connection) can start from each of these devices simultaneously one
or multiple TCP connections to one RAINS server. Firstly, it takes more time for
connecting devices to establish a TCP connection and secondly, it fills up the
connection cache which will start to evict connections (possibly active once
e.g. when a recursive lookup is performed and the query is in the pending cache)
from the cache according to its LRU strategy.

Defense: The infrastructure must be able to handle a huge number of connection
requests. In case the attacker is able to exhaust the RAM just with TCP
connections, then it is too strong (violates nr. 5)

## Attacker model 2

- Same capabilities as attacker model 1
- Can sign valid assertions either by having authority over a zone or being able
  to steal the private key from a zone's authority.

### RAM and cache exhaustion attacks

Attack 3: An attacker issues once 'non-expiring' shards (e.g. expire in 1000
years) with many contained assertions and pushes them regularly to caching
servers. Instead of pushing the shards, an attacker can as well send queries for
non-existent names in that domain and let the caching servers fetch the shards.
In regular intervals the attacker has to resend these queries to prevent the
caching servers to evict these large entries in case they use a lru policy. This
attack will probably not exhaust the cache but fill it with lots of 'garbage'
content which kind of forces the operator to increase its caching capabilities.
The validity of the shard is determined by the shortest assertion validity on
the delegation chain. The further away a zone is from the root the shorter the
lifetime of the shard is and the attacker has to resend the shard more often.
Also because there are less queries for non-existing names the entry will get
stale less quickly.

Defense [PROTOCOL CHANGE]: It is hard for a server to distinguish between a
valid and a forged query for a non-existing name. Nevertheless, a maximum shard
size restricts the attacker as he has to do more work. It also allows the
operator to have a smaller cache with the same amount of entries and evict
entries more frequently. Answering non-existence queries with a notification
message reduced the amount of data transferred over the network substantially.
If a client still wants proof of non-existence through a shard it can enable
query option 9. A caching server could use a log monitoring service which raises
an alarm in case it detects frequent queries for non-existing names.

Attack 4: Same as attack 1 but with valid signatures. This time, not only the
input queue is filling up, but also the assertion cache.

Defense: This scenario cannot or only with a huge effort be defended as the
attacker imitates common patterns of a naming system. In case the attacker is
strong enough to fill up the cache and all the buckets of the rate limiting
mechanism, then he is not part of the model (violates nr. 5)

Attack 5: An attacker can create lots of dummy delegation assertions with valid
signatures. He would then push them to a RAINS server to exhaust the delegation
assertion cache where under normal circumstances entries are only evicted after
they have been expired as the server must be able to produce a proof of all
entries in its cache. The consequences are severe in case this attack is
successful as the server might not be able to store all necessary delegations
and thus, cannot check signatures of newly incoming assertions which in turn
would fill up the pending query cache (waiting for the delegation assertion to
arrive).

Defense: Having a monitoring service which counts the number of received
delegations per zone in a configurable time interval. In case the amount of
received delegations exceed a threshold and the zone is unknown i.e. it is not a
valid zone known for having many delegations like TLDs and thus, is part of a
whitelist, the zone will be blacklisted. The problem here is that since the
attacker has authority over a zone, he can delegate to a number of sub-zones
such that the threshold is not reached and then repeat this step in each of the
sub-zones. This results also in a large amount of delegations without being
blacklisted. To restrict this defense evasion method the monitoring system can
raise an alert or blacklist zones which are more than a configurable amount of
steps away from the root.

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

Attack 12: An attacker having authority over a zone can push a message
containing a large zone to his target rains server (it is not necessary to sign
the contained assertions). The attacker then issues many queries for a
non-existent name of this zone to the target server. As the target server does
not have signed shards, it has to reply with the large zone file. This attack
will use up a large fraction of the server's network capabilities. TODO make
some calculation how many queries are necessary to saturate server components.

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

### Amplification attack

Attack 14: Query with many dots depends on configuration of server,
caching&recursive, only recursive parallel vs. sequential

Attack 15: large shards, mitigate by e.g. having max shard size 100