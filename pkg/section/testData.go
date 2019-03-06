package section

import (
	"strconv"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/bitarray"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

const (
	ip4TestAddr       = "192.0.2.0"
	ip4TestAddr2      = "198.51.100.0"
	ip4TestAddr3      = "203.0.113.0"
	ip6TestAddr       = "2001:db8::"
	ip4TestAddrCIDR24 = "192.0.2.0/24"
	ip4TestAddrCIDR32 = "192.0.2.0/32"
	ip4TestAddr2CIDR  = "198.51.100.0/24"
	ip4TestAddr3CIDR  = "203.0.113.0/24"
	ip6TestAddrCIDR   = "2001:db8::/32"
	testDomain        = "example.com."
	testZone          = "com."
	testSubjectName   = "example"
	globalContext     = "."
)

//GetZone returns an zone containing a shard, assertion with all object types and a pshard. The zone is valid.
func GetZone() *Zone {
	return &Zone{
		//FIXME CFE add pshard
		Content:     []*Assertion{GetAssertion()},
		Context:     globalContext,
		SubjectZone: testDomain,
	}
}

//GetShard returns a shard containing an assertion with all object types that is valid.
func GetShard() *Shard {
	return &Shard{
		Content:     []*Assertion{GetAssertion()},
		Context:     globalContext,
		SubjectZone: testDomain,
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
	}
}

//GetPshard returns a shard containing an assertion with all object types that is valid.
func GetPshard() *Pshard {
	return &Pshard{
		BloomFilter: GetBloomFilter(),
		Context:     globalContext,
		SubjectZone: testDomain,
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
	}
}

//GetAssertion returns an assertion containing all objects types that is valid.
func GetAssertion() *Assertion {
	return &Assertion{
		Content:     object.AllObjects(),
		Context:     globalContext,
		SubjectName: testSubjectName,
		SubjectZone: testZone,
	}
}

//Datastructure returns a datastructure object with valid content
func GetBloomFilter() BloomFilter {
	return BloomFilter{
		Algorithm: BloomKM12,
		Hash:      algorithmTypes.Shake256,
		Filter:    make(bitarray.BitArray, 32),
	}
}

//Signature returns a signature object with all fields set except signature data.
func Signature() signature.Sig {
	return signature.Sig{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			KeyPhase:  1,
			Algorithm: algorithmTypes.Ed25519,
		},
		ValidSince: time.Now().Unix(),
		ValidUntil: time.Now().Add(24 * time.Hour).Unix(),
	}
}

//AllAllowedNetworkObjects returns a list of objects that are allowed for network subjectAddresses; with valid content
func AllAllowedNetworkObjects() []object.Object {
	redirObject := object.Object{Type: object.OTRedirection, Value: testDomain}
	delegObject := object.Object{Type: object.OTDelegation, Value: object.PublicKey()}
	registrantObject := object.Object{Type: object.OTRegistrant, Value: "Registrant information"}
	return []object.Object{redirObject, delegObject, registrantObject}
}

//Notification returns a notification with all fields set
func GetNotification() *Notification {
	return &Notification{
		Token: token.New(),
		Type:  NTNoAssertionsExist,
		Data:  "Notification information",
	}
}

//NotificationNoData returns a notification with all fields set except data.
func NotificationNoData() *Notification {
	return &Notification{
		Token: token.New(),
		Type:  NTNoAssertionsExist,
	}
}

//GetQuery returns a query with all query options set and querying all types.
func GetQuery() *query.Name {
	return &query.Name{
		Context:    globalContext,
		Expiration: 50000,
		Name:       testDomain,
		Options:    AllQueryOptions(),
		Types:      AllObjectType(),
	}
}

//AllQueryOptions returns all query options
func AllQueryOptions() []query.Option {
	return []query.Option{
		query.QOCachedAnswersOnly,
		query.QOExpiredAssertionsOk,
		query.QOMinE2ELatency,
		query.QOMinInfoLeakage,
		query.QOMinLastHopAnswerSize,
		query.QONoProactiveCaching,
		query.QONoVerificationDelegation,
		query.QOTokenTracing,
	}
}

//Allobject.Types returns all object types
func AllObjectType() []object.Type {
	return []object.Type{
		object.OTCertInfo,
		object.OTDelegation,
		object.OTExtraKey,
		object.OTInfraKey,
		object.OTIP4Addr,
		object.OTIP6Addr,
		object.OTScionAddr4,
		object.OTScionAddr6,
		object.OTName,
		object.OTNameset,
		object.OTNextKey,
		object.OTRedirection,
		object.OTRegistrant,
		object.OTRegistrar,
		object.OTServiceInfo,
	}
}

func sortedAssertions(nof int) []*Assertion {
	assertions := []*Assertion{}
	objs := object.SortedObjects(13)
	for i := 0; i < nof; i++ {
		for j := 0; j < nof; j++ {
			for k := 0; k < nof; k++ {
				//TODO CFE extend this test when we support multiple connection per assertion
				for l := 0; l < 78; l++ {
					assertions = append(assertions, &Assertion{
						SubjectName: strconv.Itoa(i),
						SubjectZone: strconv.Itoa(j),
						Context:     strconv.Itoa(k),
						Content:     []object.Object{objs[l]},
					})
				}
			}
		}
	}
	assertions = append(assertions, assertions[len(assertions)-1]) //equals
	return assertions
}

func sortedShards(nof int) []*Shard {
	shards := []*Shard{}
	assertions := sortedAssertions(2)
	for i := 0; i < nof; i++ {
		for j := 0; j < nof; j++ {
			for k := 0; k < nof; k++ {
				for l := 0; l < nof; l++ {
					for m := 0; m < 312; m++ {
						shards = append(shards, &Shard{
							SubjectZone: strconv.Itoa(i),
							Context:     strconv.Itoa(j),
							RangeFrom:   strconv.Itoa(k),
							RangeTo:     strconv.Itoa(l),
							Content:     []*Assertion{assertions[m]},
						})
					}
				}
			}
		}
	}
	shards = append(shards, shards[len(shards)-1]) //equals
	return shards
}

func sortedBloomFilters(nof int) []BloomFilter {
	bf := []BloomFilter{}
	for i := 0; i < 4; i++ {
		for j := 0; j < 3; j++ {
			for m := 0; m < nof; m++ {
				bf = append(bf, BloomFilter{
					Algorithm: BloomFilterAlgo(i),
					Hash:      algorithmTypes.Hash(j + 4),
					Filter:    make(bitarray.BitArray, 8*(1+m)),
				})
			}
		}
	}
	bf = append(bf, bf[len(bf)-1]) //equals
	return bf
}

func sortedPshards(nof int) []*Pshard {
	pshards := []*Pshard{}
	bfs := sortedBloomFilters(1)
	for i := 0; i < nof; i++ {
		for j := 0; j < nof; j++ {
			for k := 0; k < nof; k++ {
				for l := 0; l < nof; l++ {
					for m := 0; m < 12; m++ {
						pshards = append(pshards, &Pshard{
							SubjectZone: strconv.Itoa(i),
							Context:     strconv.Itoa(j),
							RangeFrom:   strconv.Itoa(k),
							RangeTo:     strconv.Itoa(l),
							BloomFilter: bfs[m],
						})
					}
				}
			}
		}
	}
	pshards = append(pshards, pshards[len(pshards)-1]) //equals
	return pshards
}

func sortedZones(nof int) []*Zone {
	zones := []*Zone{}
	assertions := sortedAssertions(2)
	for i := 0; i < nof; i++ {
		for j := 0; j < nof; j++ {
			for m := 0; m < 128; m++ {
				zones = append(zones, &Zone{
					SubjectZone: strconv.Itoa(i),
					Context:     strconv.Itoa(j),
					Content:     []*Assertion{assertions[m]},
				})
			}
		}
	}
	zones = append(zones, zones[len(zones)-1]) //equals
	return zones
}

func sortedNotifications(nofNotifications int) []*Notification {
	notifications := []*Notification{}
	tokens := sortedTokens(nofNotifications)
	typeNumbers := []int{100, 399, 400, 403, 404, 413, 500, 501, 504}
	for i := 0; i < nofNotifications; i++ {
		nofTypes := nofNotifications
		if nofTypes > 9 {
			nofTypes = 9
		}
		for j := 0; j < nofTypes; j++ {
			for k := 0; k < nofNotifications; k++ {
				notifications = append(notifications, &Notification{
					Token: tokens[i],
					Type:  NotificationType(typeNumbers[j]),
					Data:  strconv.Itoa(k),
				})
			}
		}
	}
	notifications = append(notifications, notifications[len(notifications)-1])
	return notifications
}

//nofTokens must be smaller than 256
func sortedTokens(nofTokens int) []token.Token {
	if nofTokens > 255 {
		log.Error("nofTokens must be smaller than 256", "nofTokens", nofTokens)
		return nil
	}
	tokens := []token.Token{}
	for i := 0; i < nofTokens; i++ {
		token := token.Token{}
		copy(token[:], []byte{byte(i)})
		tokens = append(tokens, token)
	}
	return tokens
}
