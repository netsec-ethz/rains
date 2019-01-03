package cache

import (
	"net"

	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

//Connection stores persistent stream-oriented network connections.
type Connection interface {
	//AddConnection adds conn to the cache. If the cache capacity is reached, a connection from the cache will be
	//chosen by some metric, closed and removed.
	AddConnection(conn net.Conn)
	//AddCapability adds capabilities to the destAddr entry. It returns false if there is no entry
	//in the cache for dstAddr. If there is already a capability list associated with destAddr, it
	//will be overwritten.
	AddCapabilityList(dstAddr net.Addr, capabilities []message.Capability) bool
	//GetConnection returns true and all cached connections to dstAddr.
	//GetConnection returns false if there is no cached connection to dstAddr.
	GetConnection(dstAddr net.Addr) ([]net.Conn, bool)
	//Get returns true and the capability list of dstAddr.
	//Get returns false if there is no capability list of dstAddr.
	GetCapabilityList(dstAddr net.Addr) ([]message.Capability, bool)
	//CloseAndRemoveConnection closes conn and removes it from the cache.
	CloseAndRemoveConnection(conn net.Conn)
	//CloseAndRemoveConnections closes and removes all cached connections to addr
	CloseAndRemoveConnections(addr net.Addr)
	//Len returns the number of connections currently in the cache.
	Len() int
}

//Capability stores a mapping from a hash of a capability list to a pointer of the list.
type Capability interface {
	//Add normalizes and serializes capabilities and then calculates a sha256 hash over it. It then
	//stores the mapping from the hash to a pointer of the list.
	//If the cache is full it removes a capability according to some metric
	Add(capabilities []message.Capability)
	//Get returns true and a pointer to the capability list from which the hash was taken if
	//present, otherwise false and nil.
	Get(hash []byte) ([]message.Capability, bool)
	//Len returns the number of elements currently in the cache.
	Len() int
}

//ZonePublicKey is used to store public keys of zones and a pointer to delegation assertions
//containing them.
type ZonePublicKey interface {
	//Add adds publicKey together with the assertion containing it to the cache. Returns false if
	//the cache exceeds a configured (during initialization of the cache) amount of entries. If the
	//cache is full it removes a public key according to some metric. The cache logs a message when
	//a zone has more than a certain (configurable) amount of public keys. (An external service can
	//then decide if it wants to blacklist a given zone). If the internal flag is set, the publicKey
	//will only be removed after it expired.
	Add(assertion *section.Assertion, publicKey keys.PublicKey, internal bool) bool
	//Get returns true, the assertion holding the returned public key, and a non expired public key
	//which can be used to verify a signature with sigMetaData. It returns false if there is no
	//valid matching public key in the cache.
	Get(zone, context string, sigMetaData signature.MetaData) (
		keys.PublicKey, *section.Assertion, bool)
	//RemoveExpiredKeys deletes all expired public keys from the cache.
	RemoveExpiredKeys()
	//Len returns the number of public keys currently in the cache.
	Len() int
}

//FIXME remove after new implementation is tested
/*type PendingKeyCacheOld interface {
	//Add adds sectionSender to the cache and returns true if a new delegation should be sent.
	Add(sectionSender util.MsgSectionSender, algoType algorithmTypes.Signature, phase int) bool
	//AddToken adds token to the token map where the value of the map corresponds to the cache entry
	//matching the given zone and cotext. Token is added to the map and the cache entry's token,
	//expiration and sendTo fields are updated only if a matching cache entry exists. False is
	//returned if no matching cache entry exists.
	AddToken(token token.Token, expiration int64, sendTo net.Addr, zone, context string) bool
	//GetAndRemove returns all sections who contain a signature matching the given parameter and
	//deletes them from the cache. The token map is updated if necessary.
	GetAndRemove(zone, context string, algoType algorithmTypes.Signature, phase int) []util.MsgSectionSender
	//GetAndRemoveByToken returns all sections who correspond to token and deletes them from the
	//cache. Token is removed from the token map.
	GetAndRemoveByToken(token token.Token) []util.MsgSectionSender
	//ContainsToken returns true if token is in the token map.
	ContainsToken(token token.Token) bool
	//RemoveExpiredValues deletes all sections of an expired entry and updates the token map if
	//necessary. It logs which sections are removed and to which server the query has been sent.
	RemoveExpiredValues()
	//Len returns the number of sections in the cache
	Len() int
}*/

type PendingKey interface {
	//Add adds ss to the cache together with the token and expiration time of the query sent to the
	//host with the addr defined in ss.
	Add(ss util.MsgSectionSender, t token.Token, expiration int64)
	//GetAndRemove returns util.MsgSectionSender which corresponds to token and true, and deletes it from
	//the cache. False is returned if no util.MsgSectionSender matched token.
	GetAndRemove(t token.Token) (util.MsgSectionSender, bool)
	//ContainsToken returns true if t is cached
	ContainsToken(t token.Token) bool
	//RemoveExpiredValues deletes all expired entries. It logs the host's addr which was not able to
	//respond in time.
	RemoveExpiredValues()
	//Len returns the number of sections in the cache
	Len() int
}

//FIXME remove after new implementation is tested
/*type PendingQueryCacheOld interface {
	//Add adds sectionSender to the cache and returns false if the query is already in the cache.
	Add(sectionSender util.MsgSectionSender) bool
	//AddToken adds token to the token map where the value of the map corresponds to the cache entry
	//matching the given (fully qualified) name, context and connection (sorted). Token is added to the
	//map and the cache entry's token, expiration and sendTo fields are updated only if a matching
	//cache entry exists. False is returned if no matching cache entry exists.
	AddToken(token token.Token, expiration int64, sendTo net.Addr, name, context string,
		types []object.Type) bool
	//GetQuery returns true and the query or addressQuery stored with token in the cache if there is
	//such an entry.
	GetQuery(token token.Token) (section.Section, bool)
	//AddAnswerByToken adds section to the cache entry matching token with the given deadline. It
	//returns true if there is a matching token in the cache and section is not already stored for
	//these pending queries. The pending queries are are not removed from the cache.
	AddAnswerByToken(section section.WithSig, token token.Token, deadline int64) bool
	//GetAndRemoveByToken returns all queries waiting for a response to a query message containing
	//token and deletes them from the cache if no other section has been added to this cache entry
	//since section has been added by AddAnswerByToken(). Token is removed from the token map.
	GetAndRemoveByToken(token token.Token, deadline int64) (
		[]util.MsgSectionSender, []section.Section)
	//UpdateToken adds newToken to the token map, lets it point to the cache value pointed by
	//oldToken and removes oldToken from the token map if newToken is not already in the token map.
	//It returns false if there is already an entry for newToken in the token map.
	UpdateToken(oldToken, newToken token.Token) bool
	//RemoveExpiredValues deletes all queries of an expired entry and updates the token map if
	//necessary. It logs which queries are removed and from which server the query has come and to
	//which it has been sent.
	RemoveExpiredValues()
	//Len returns the number of queries in the cache
	Len() int
}*/

type PendingQuery interface {
	//Add checks if this server has already forwarded a msg containing the same queries as ss. If
	//this is the case, ss is added to the cache and false is returned. If not, ss is added together
	//with t and expiration to the cache and true is returned.
	Add(ss util.MsgSectionSender, t token.Token, expiration int64) bool
	//GetAndRemove returns all util.MsgSectionSenders which correspond to token and delete them from the
	//cache.
	GetAndRemove(t token.Token) []util.MsgSectionSender
	//RemoveExpiredValues deletes all expired entries.
	RemoveExpiredValues()
	//Len returns the number of sections in the cache
	Len() int
}

//Assertion is used to store and efficiently lookup assertions
type Assertion interface {
	//Add adds an assertion together with an expiration time (number of seconds since 01.01.1970) to
	//the cache. It returns false if the cache is full and a non internal element has been removed
	//according to some strategy. It also adds assertion to the consistency cache.
	Add(assertion *section.Assertion, expiration int64, isInternal bool) bool
	//Get returns true and a set of assertions matching the given key if there exist some. Otherwise
	//nil and false is returned. If strict is set only an exact match for the provided FQDN is returned
	// otherwise a search up the domain name hiearchy is performed.
	Get(fqdn, context string, objType object.Type, strict bool) ([]*section.Assertion, bool)
	//RemoveExpiredValues goes through the cache and removes all expired assertions from the
	//assertionCache and the consistency cache.
	RemoveExpiredValues()
	//RemoveZone deletes all assertions in the assertionCache and consistencyCache of the given
	//zone.
	RemoveZone(zone string)
	//Len returns the number of elements in the cache.
	Len() int
}

type NegativeAssertion interface {
	//Add adds shard together with an expiration time (number of seconds since 01.01.1970) to
	//the cache. It returns false if the cache is full and a non internal element has been removed
	//according to some strategy. It also adds shard to the consistency cache.
	AddShard(shard *section.Shard, expiration int64, isInternal bool) bool
	//Add adds pshard together with an expiration time (number of seconds since 01.01.1970) to
	//the cache. It returns false if the cache is full and a non internal element has been removed
	//according to some strategy. It also adds shard to the consistency cache.
	AddPshard(pshard *section.Pshard, expiration int64, isInternal bool) bool
	//Add adds zone together with an expiration time (number of seconds since 01.01.1970) to
	//the cache. It returns false if the cache is full and a non internal element has been removed
	//according to some strategy. It also adds zone to the consistency cache.
	AddZone(zone *section.Zone, expiration int64, isInternal bool) bool
	//Get returns true and a set of shards and zones matching subjectZone and context and overlap
	//with interval if there exist some. When context is the empty string, a random context is
	//chosen. Otherwise nil and false is returned.
	Get(subjectZone, context string, interval section.Interval) ([]section.WithSigForward, bool)
	//RemoveExpiredValues goes through the cache and removes all expired shards and zones from the
	//assertionCache and the consistency cache.
	RemoveExpiredValues()
	//RemoveZone deletes all shards and zones in the assertionCache and consistencyCache of the
	//given subjectZone.
	RemoveZone(subjectZone string)
	//Len returns the number of elements in the cache.
	Len() int
}
