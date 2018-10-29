package rainsd

import (
	"fmt"
	"sort"
	"sync"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/section"
)

//isAssertionConsistent checks if the incoming assertion is consistent with the elements in the cache.
//If not, every element of this zone and context is dropped and it returns false
func isAssertionConsistent(assertion *section.Assertion, consistCache consistencyCache,
	assertionsCache assertionCache, negAssertionCache negativeAssertionCache) bool {
	negAssertions := consistCache.Get(assertion.Context, assertion.SubjectZone, assertion)
	for _, negAssertion := range negAssertions {
		switch negAssertion := negAssertion.(type) {
		case *section.Assertion:
			//TODO CFE do nothing???
		case *section.Shard:
			if togetherValid(assertion, negAssertion) && !shardContainsAssertion(assertion, negAssertion) {
				log.Warn("Inconsistency encountered between assertion and shard. Drop all sections for given context and zone.", "assertion", assertion, "shard", negAssertion)
				dropAllWithContextZone(assertion.Context, assertion.SubjectZone, assertionsCache, negAssertionCache)
				return false
			}
		case *section.Zone:
			if togetherValid(assertion, negAssertion) && !zoneContainsAssertion(assertion, negAssertion) {
				dropAllWithContextZone(assertion.Context, assertion.SubjectZone, assertionsCache, negAssertionCache)
				return false
			}
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *Shard or *Zone. Got=%T", negAssertion))
		}
	}
	return true
}

//isShardConsistent checks if the incoming shard is consistent with the elements in the cache.
//If not every element of this zone is dropped and it return false
func isShardConsistent(shard *section.Shard, consistCache consistencyCache,
	assertionsCache assertionCache, negAssertionCache negativeAssertionCache) bool {
	secs := consistCache.Get(shard.Context, shard.SubjectZone, shard)
	for _, v := range secs {
		switch v := v.(type) {
		case *section.Assertion:
			if togetherValid(shard, v) && !shardContainsAssertion(v, shard) {
				dropAllWithContextZone(shard.Context, shard.SubjectZone, assertionsCache, negAssertionCache)
				return false
			}
		case *section.Shard:
			if togetherValid(shard, v) && !isShardConsistentWithShard(shard, v) {
				dropAllWithContextZone(shard.Context, shard.SubjectZone, assertionsCache, negAssertionCache)
				return false
			}
		case *section.Zone:
			if togetherValid(shard, v) && !isShardConsistentWithZone(shard, v) {
				dropAllWithContextZone(shard.Context, shard.SubjectZone, assertionsCache, negAssertionCache)
				return false
			}
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *Shard or *Zone. Got=%T", v))
		}
	}
	return true
}

//isZoneConsistent checks if the incoming zone is consistent with the elements in the cache.
//If not every element of this zone is dropped and it return false
func isZoneConsistent(zone *section.Zone, assertionsCache assertionCache,
	negAssertionCache negativeAssertionCache) bool {
	secs, ok := negAssertionCache.Get(zone.Context, zone.SubjectZone, zone)
	if ok {
		for _, v := range secs {
			switch v := v.(type) {
			case *section.Assertion:
				if togetherValid(zone, v) && !zoneContainsAssertion(v, zone) {
					dropAllWithContextZone(zone.Context, zone.SubjectZone, assertionsCache, negAssertionCache)
					return false
				}
			case *section.Shard:
				if togetherValid(zone, v) && !isShardConsistentWithZone(v, zone) {
					dropAllWithContextZone(zone.Context, zone.SubjectZone, assertionsCache, negAssertionCache)
					return false
				}
			case *section.Zone:
				if togetherValid(zone, v) && !isZoneConsistentWithZone(v, zone) {
					dropAllWithContextZone(zone.Context, zone.SubjectZone, assertionsCache, negAssertionCache)
					return false
				}
			default:
				log.Warn(fmt.Sprintf("Not supported type. Expected *Shard or *Zone. Got=%T", v))
			}
		}
	}
	return true
}

//isAddressAssertionConsistent checks if the incoming address assertion is consistent with the elements in the cache.
//If not, every element of this zone and context is dropped and it returns false
func isAddressAssertionConsistent(assertion *section.AddrAssertion) bool {
	//TODO CFE implement
	return false
}

//togetherValid returns true if both sections are at some point both valid
func togetherValid(s1, s2 section.WithSig) bool {
	return s1.ValidUntil() >= s2.ValidSince() && s1.ValidSince() <= s2.ValidUntil()
}

//dropAllWithContextZone deletes all assertions, shards and zones in the cache with the given context and zone
func dropAllWithContextZone(context, zone string, assertionsCache assertionCache,
	negAssertionCache negativeAssertionCache) {
	assertionsCache.RemoveZone(zone)
	negAssertionCache.RemoveZone(zone)
}

//shardContainsAssertion returns true if the given shard contains the given assertion
func shardContainsAssertion(a *section.Assertion, s *section.Shard) bool {
	for _, assertion := range s.Content {
		if a.EqualContextZoneName(assertion) {
			return true
		}
	}
	log.Warn("Encountered valid assertion together with a valid shard that does not contain it.", "assertion", *a, "shard", *s)
	return false
}

//zoneContainsAssertion returns true if the given zone contains the given assertion and that all contained shards in range of the assertion contain the assertion.
func zoneContainsAssertion(a *section.Assertion, z *section.Zone) bool {
	isContained := false //checks that zone contains given assertion
	for _, v := range z.Content {
		switch v := v.(type) {
		case *section.Assertion:
			if a.EqualContextZoneName(v) {
				isContained = true
			}
		case *section.Shard:
			if v.RangeFrom < a.SubjectName && v.RangeTo > a.SubjectName {
				if shardContainsAssertion(a, v) { //checks that all shards in range contain the assertion
					isContained = true
				} else {
					return false
				}
			}
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *Shard or *Assertion. Got=%T", v))
			return false
		}
		log.Warn("Encountered valid assertion together with a valid zone that does not contain it.", "assertion", *a, "zone", *z)
	}
	return isContained
}

//isShardConsistentWithShard returns true if both shards are consistent with each other
//This is the case when all assertions in the intersecting interval are present in both shards
func isShardConsistentWithShard(s1, s2 *section.Shard) bool {
	v1 := &sortedAssertions{assertions: []*section.Assertion{}}
	v2 := &sortedAssertions{assertions: []*section.Assertion{}}
	addAssertionsinRangeToList(s1, s2, v1)
	addAssertionsinRangeToList(s2, s1, v2)
	return v1.Equal(v2)
}

//isShardConsistentWithZone returns true if the shard is consistent with the zone
func isShardConsistentWithZone(s *section.Shard, z *section.Zone) bool {
	assertionsInZone := &sortedAssertions{assertions: []*section.Assertion{}}
	//check that all elements of the zone in the range of the shard are also contained in the shard
	for _, v := range z.Content {
		switch v := v.(type) {
		case *section.Assertion:
			if v.SubjectName > s.RangeFrom && v.SubjectName < s.RangeTo {
				if !shardContainsAssertion(v, s) {
					log.Warn("Shard is not consistent with zone. Zone contains assertion in range of shard which is missing in shard")
					return false
				}
			}
			assertionsInZone.Add(v)
		case *section.Shard:
			if !isShardConsistentWithShard(v, s) {
				log.Warn("Shard is not consistent with zone. Zone contains shard in range of another shard which are not consistent")
				return false
			}
			addAssertionsinRangeToList(v, section.TotalInterval{}, assertionsInZone)
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *Shard or *Assertion. Got=%T", v))
		}
	}
	//check that all elements of the shard are also contained in the zone.
	for _, a := range s.Content {
		_, ok := assertionsInZone.Get(a)
		if !ok {
			assertions, _ := assertionsInZone.Get(section.TotalInterval{}) //only used for logging
			log.Warn("Shard is not consistent with zone. Shard contains an assertion which is not contained in the zone", "zone", z,
				"assertionInZone", assertions, "shard", s)
			return false
		}
	}
	return true
}

func isZoneConsistentWithZone(z1, z2 *section.Zone) bool {
	assertionsInZone1 := &sortedAssertions{assertions: []*section.Assertion{}}
	assertionsInZone2 := &sortedAssertions{assertions: []*section.Assertion{}}
	for _, v := range z1.Content {
		switch v := v.(type) {
		case *section.Assertion:
			if !zoneContainsAssertion(v, z2) {
				return false
			}
			assertionsInZone1.Add(v)
		case *section.Shard:
			for _, val := range z2.Content {
				switch val := val.(type) {
				case *section.Assertion:
					if !shardContainsAssertion(val, v) {
						return false
					}
				case *section.Shard:
					if !isShardConsistentWithShard(val, v) {
						return false
					}
				default:
					log.Warn(fmt.Sprintf("Not supported type. Expected *Shard or *Assertion. Got=%T", v))
				}
			}
			addAssertionsinRangeToList(v, section.TotalInterval{}, assertionsInZone1)
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *Shard or *Assertion. Got=%T", v))
		}
	}
	//check that there is no assertion in z2 which is missing in z1.
	for _, v := range z2.Content {
		switch v := v.(type) {
		case *section.Assertion:
			assertionsInZone2.Add(v)
		case *section.Shard:
			addAssertionsinRangeToList(v, section.TotalInterval{}, assertionsInZone2)
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *Shard or *Assertion. Got=%T", v))
		}
	}
	if !assertionsInZone1.Equal(assertionsInZone2) {
		return false
	}
	return true
}

//containedShardsAreConsistent checks that all contained shards are mutually consistent and also consistent with the contained assertions.
func containedShardsAreConsistent(z *section.Zone) bool {
	for i, v := range z.Content {
		switch v := v.(type) {
		case *section.Assertion:
			for _, val := range z.Content[i+1:] {
				switch val := val.(type) {
				case *section.Assertion:
				//assertion is always consistent with another assertion
				case *section.Pshard:
					log.Info("Not yet implemented")
				case *section.Shard:
					if val.RangeFrom < v.SubjectName && val.RangeTo > v.SubjectName && !shardContainsAssertion(v, val) {
						log.Info("zone is internally not consistent. Zone contains an assertion which is not present in a shard in the range",
							"assertion", *v, "shard", *val)
						return false
					}
				default:
					log.Warn(fmt.Sprintf("Not supported type. Expected *Shard or *Assertion. Got=%T", v))
				}
			}
		case *section.Shard:
			for _, val := range z.Content[i+1:] {
				switch val := val.(type) {
				case *section.Assertion:
					if v.RangeFrom < val.SubjectName && v.RangeTo > val.SubjectName && !shardContainsAssertion(val, v) {
						log.Info("zone is internally not consistent. Zone contains an assertion which is not present in a shard in the range",
							"assertion", *val, "shard", *v)
						return false
					}
				case *section.Pshard:
					log.Info("Not yet implemented")
				case *section.Shard:
					if val.RangeFrom < v.RangeTo && val.RangeTo > v.RangeFrom && !isShardConsistentWithShard(v, val) {
						log.Info("zone is internally not consistent. Zone contains a shard which is not consistent with another shard")
						return false
					}
				default:
					log.Warn(fmt.Sprintf("Not supported type. Expected *Shard or *Assertion. Got=%T", v))
				}
			}
		case *section.Pshard:
			log.Info("Not yet implemented")
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *Shard or *Assertion. Got=%T", v))
		}
	}
	return true
}

//addAssertionsinRangeToList adds all assertions from s which are in the range of interval to the returned sortedAssertions list
func addAssertionsinRangeToList(s *section.Shard, interval section.Interval, list *sortedAssertions) {
	for _, a := range s.Content {
		if a.SubjectName > interval.Begin() && a.SubjectName < interval.End() {
			list.Add(a)
		}
	}
}

type sortedAssertions struct {
	assertions     []*section.Assertion
	assertionsLock sync.RWMutex
}

//Add adds the assertion to the sorted list at the correct position.
//It returns true if it added a and false if a is already contained
func (s *sortedAssertions) Add(a *section.Assertion) bool {
	s.assertionsLock.Lock()
	defer s.assertionsLock.Unlock()
	i := sort.Search(len(s.assertions), func(i int) bool {
		return s.assertions[i].SubjectName >= a.SubjectName
	})
	if i != len(s.assertions) && s.assertions[i].EqualContextZoneName(a) {
		return false
	}
	s.assertions = append(s.assertions[:i], append([]*section.Assertion{a}, s.assertions[i:]...)...)
	return true
}

//Delete removes the assertion from the sorted list.
//Returns true if element was successfully deleted from the list. If a not part of list returns false
func (s *sortedAssertions) Delete(a *section.Assertion) bool {
	s.assertionsLock.Lock()
	defer s.assertionsLock.Unlock()
	i := sort.Search(len(s.assertions), func(i int) bool {
		return s.assertions[i].SubjectName >= a.SubjectName
	})
	if !s.assertions[i].EqualContextZoneName(a) {
		return false
	}
	s.assertions = append(s.assertions[:i], s.assertions[i+1:]...)
	return true
}

//Len returns the number of element in this sorted slice
func (s *sortedAssertions) Len() int {
	s.assertionsLock.RLock()
	defer s.assertionsLock.RUnlock()
	return len(s.assertions)
}

//Get returns true and all assertions which are in the given interval if there are any
func (s *sortedAssertions) Get(interval section.Interval) ([]*section.Assertion, bool) {
	s.assertionsLock.RLock()
	defer s.assertionsLock.RUnlock()
	elements := []*section.Assertion{}
	i := sort.Search(len(s.assertions), func(i int) bool {
		return s.assertions[i].SubjectName >= interval.Begin()
	})
	if i == len(s.assertions) {
		return nil, false
	}
	if s.assertions[i].SubjectName < interval.Begin() {
		return elements, false
	}
	for ; i < len(s.assertions); i++ {
		if s.assertions[i].SubjectName > interval.End() {
			break
		}
		elements = append(elements, s.assertions[i])
	}
	return elements, len(elements) > 0
}

//Equal returns true if both list contain the same assertions where the EqualContextZoneName method on assertions is used to compare them.
func (s *sortedAssertions) Equal(s2 *sortedAssertions) bool {
	s.assertionsLock.RLock()
	s2.assertionsLock.RLock()
	defer s.assertionsLock.RUnlock()
	defer s2.assertionsLock.RUnlock()
	for i := 0; i < len(s.assertions); i++ {
		if !s.assertions[i].EqualContextZoneName(s2.assertions[i]) {
			return false
		}
	}
	return true
}
