package rainsd

import (
	"fmt"
	"rains/rainslib"
	"sort"
	"sync"

	log "github.com/inconshreveable/log15"
)

//isAssertionConsistent checks if the incoming assertion is consistent with the elements in the cache.
//If not, every element of this zone and context is dropped and it returns false
func isAssertionConsistent(assertion *rainslib.AssertionSection) bool {
	negAssertions, _ := negAssertionCache.GetAll(assertion.Context, assertion.SubjectZone, assertion)
	for _, negAssertion := range negAssertions {
		switch negAssertion := negAssertion.(type) {
		case *rainslib.ShardSection:
			if togetherValid(assertion, negAssertion) && !shardContainsAssertion(assertion, negAssertion) {
				log.Warn("Inconsistency encountered between assertion and shard. Drop all sections for given context and zone.", "assertion", assertion, "shard", negAssertion)
				dropAllWithContextZone(assertion.Context, assertion.SubjectZone)
				return false
			}
		case *rainslib.ZoneSection:
			if togetherValid(assertion, negAssertion) && !zoneContainsAssertion(assertion, negAssertion) {
				dropAllWithContextZone(assertion.Context, assertion.SubjectZone)
				return false
			}
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *ZoneSection. Got=%T", negAssertion))
		}
	}
	return true
}

//isShardConsistent checks if the incoming shard is consistent with the elements in the cache.
//If not every element of this zone is dropped and it return false
func isShardConsistent(shard *rainslib.ShardSection) bool {
	//check against cached assertions
	assertions, ok := assertionsCache.GetInRange(shard.Context, shard.SubjectZone, shard)
	if ok {
		for _, a := range assertions {
			if togetherValid(shard, a) && !shardContainsAssertion(a, shard) {
				dropAllWithContextZone(shard.Context, shard.SubjectZone)
				return false
			}
		}
	}
	//check against cached shards and zones
	sections, ok := negAssertionCache.GetAll(shard.Context, shard.SubjectZone, shard)
	if ok {
		for _, v := range sections {
			switch v := v.(type) {
			case *rainslib.ShardSection:
				if togetherValid(shard, v) && !isShardConsistentWithShard(shard, v) {
					dropAllWithContextZone(shard.Context, shard.SubjectZone)
					return false
				}
			case *rainslib.ZoneSection:
				if togetherValid(shard, v) && !isShardConsistentWithZone(shard, v) {
					dropAllWithContextZone(shard.Context, shard.SubjectZone)
					return false
				}
			default:
				log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *ZoneSection. Got=%T", v))
			}
		}
	}
	return true
}

//isZoneConsistent checks if the incoming zone is consistent with the elements in the cache.
//If not every element of this zone is dropped and it return false
func isZoneConsistent(zone *rainslib.ZoneSection) bool {
	//check against cached assertions
	assertions, _ := assertionsCache.GetInRange(zone.Context, zone.SubjectZone, zone)
	for _, a := range assertions {
		if togetherValid(zone, a) && !zoneContainsAssertion(a, zone) {
			dropAllWithContextZone(zone.Context, zone.SubjectZone)
			return false
		}
	}
	//check against cached shards and zones
	sections, ok := negAssertionCache.GetAll(zone.Context, zone.SubjectZone, zone)
	if ok {
		for _, v := range sections {
			switch v := v.(type) {
			case *rainslib.ShardSection:
				if togetherValid(zone, v) && !isShardConsistentWithZone(v, zone) {
					dropAllWithContextZone(zone.Context, zone.SubjectZone)
					return false
				}
			case *rainslib.ZoneSection:
				if togetherValid(zone, v) && !isZoneConsistentWithZone(v, zone) {
					dropAllWithContextZone(zone.Context, zone.SubjectZone)
					return false
				}
			default:
				log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *ZoneSection. Got=%T", v))
			}
		}
	}
	return true
}

//togetherValid returns true if both sections are at some point both valid
func togetherValid(s1, s2 rainslib.MessageSectionWithSig) bool {
	return s1.ValidUntil() >= s2.ValidSince() && s1.ValidSince() <= s2.ValidUntil()
}

//dropAllWithContextZone deletes all assertions, shards and zones in the cache with the given context and zone
func dropAllWithContextZone(context, zone string) {
	assertions, _ := assertionsCache.GetInRange(context, zone, rainslib.TotalInterval{})
	for _, a := range assertions {
		assertionsCache.Remove(a)
	}
	negAssertionCache.Remove(context, zone)
}

//shardContainsAssertion returns true if the given shard contains the given assertion
func shardContainsAssertion(a *rainslib.AssertionSection, s *rainslib.ShardSection) bool {
	for _, assertion := range s.Content {
		if a.EqualContextZoneName(assertion) {
			return true
		}
	}
	log.Warn("Encountered valid assertion together with a valid shard that does not contain it.", "assertion", *a, "shard", *s)
	return false
}

//zoneContainsAssertion returns true if the given zone contains the given assertion and that all contained shards in range of the assertion contain the assertion.
func zoneContainsAssertion(a *rainslib.AssertionSection, z *rainslib.ZoneSection) bool {
	isContained := false //checks that zone contains given assertion
	for _, v := range z.Content {
		switch v := v.(type) {
		case *rainslib.AssertionSection:
			if a.EqualContextZoneName(v) {
				isContained = true
			}
		case *rainslib.ShardSection:
			if v.RangeFrom < a.SubjectName && v.RangeTo > a.SubjectName {
				if shardContainsAssertion(a, v) { //checks that all shards in range contain the assertion
					isContained = true
				} else {
					return false
				}
			}
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", v))
			return false
		}
		log.Warn("Encountered valid assertion together with a valid zone that does not contain it.", "assertion", *a, "zone", *z)
	}
	return isContained
}

//isShardConsistentWithShard returns true if both shards are consistent with each other
//This is the case when all assertions in the intersecting interval are present in both shards
func isShardConsistentWithShard(s1, s2 *rainslib.ShardSection) bool {
	v1 := &sortedAssertions{assertions: []*rainslib.AssertionSection{}}
	v2 := &sortedAssertions{assertions: []*rainslib.AssertionSection{}}
	addAssertionsinRangeToList(s1, s2, v1)
	addAssertionsinRangeToList(s2, s1, v2)
	return v1.Equal(v2)
}

//isShardConsistentWithZone returns true if the shard is consistent with the zone
func isShardConsistentWithZone(s *rainslib.ShardSection, z *rainslib.ZoneSection) bool {
	assertionsInZone := &sortedAssertions{assertions: []*rainslib.AssertionSection{}}
	//check that all elements of the zone in the range of the shard are also contained in the shard
	for _, v := range z.Content {
		switch v := v.(type) {
		case *rainslib.AssertionSection:
			if v.SubjectName > s.RangeFrom && v.SubjectName < s.RangeTo {
				if !shardContainsAssertion(v, s) {
					log.Warn("Shard is not consistent with zone. Zone contains assertion in range of shard which is missing in shard")
					return false
				}
			}
			assertionsInZone.Add(v)
		case *rainslib.ShardSection:
			if !isShardConsistentWithShard(v, s) {
				log.Warn("Shard is not consistent with zone. Zone contains shard in range of another shard which are not consistent")
				return false
			}
			addAssertionsinRangeToList(v, rainslib.TotalInterval{}, assertionsInZone)
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", v))
		}
	}
	//check that all elements of the shard are also contained in the zone.
	for _, a := range s.Content {
		_, ok := assertionsInZone.Get(a)
		if !ok {
			assertions, _ := assertionsInZone.Get(rainslib.TotalInterval{}) //only used for logging
			log.Warn("Shard is not consistent with zone. Shard contains an assertion which is not contained in the zone", "zone", z,
				"assertionInZone", assertions, "shard", s)
			return false
		}
	}
	return true
}

func isZoneConsistentWithZone(z1, z2 *rainslib.ZoneSection) bool {
	assertionsInZone1 := &sortedAssertions{assertions: []*rainslib.AssertionSection{}}
	assertionsInZone2 := &sortedAssertions{assertions: []*rainslib.AssertionSection{}}
	for _, v := range z1.Content {
		switch v := v.(type) {
		case *rainslib.AssertionSection:
			if !zoneContainsAssertion(v, z2) {
				return false
			}
			assertionsInZone1.Add(v)
		case *rainslib.ShardSection:
			for _, val := range z2.Content {
				switch val := val.(type) {
				case *rainslib.AssertionSection:
					if !shardContainsAssertion(val, v) {
						return false
					}
				case *rainslib.ShardSection:
					if !isShardConsistentWithShard(val, v) {
						return false
					}
				default:
					log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", v))
				}
			}
			addAssertionsinRangeToList(v, rainslib.TotalInterval{}, assertionsInZone1)
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", v))
		}
	}
	//check that there is no assertion in z2 which is missing in z1.
	for _, v := range z2.Content {
		switch v := v.(type) {
		case *rainslib.AssertionSection:
			assertionsInZone2.Add(v)
		case *rainslib.ShardSection:
			addAssertionsinRangeToList(v, rainslib.TotalInterval{}, assertionsInZone2)
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", v))
		}
	}
	if !assertionsInZone1.Equal(assertionsInZone2) {
		return false
	}
	return true
}

//containedShardsAreConsistent checks that all contained shards are mutually consistent and also consistent with the contained assertions.
func containedShardsAreConsistent(z *rainslib.ZoneSection) bool {
	for i, v := range z.Content {
		switch v := v.(type) {
		case *rainslib.AssertionSection:
			for _, val := range z.Content[i+1:] {
				switch val := val.(type) {
				case *rainslib.AssertionSection:
				//assertion is always consistent with another assertion
				case *rainslib.ShardSection:
					if val.RangeFrom < v.SubjectName && val.RangeTo > v.SubjectName && !shardContainsAssertion(v, val) {
						log.Info("zone is internally not consistent. Zone contains an assertion which is not present in a shard in the range",
							"assertion", *v, "shard", *val)
						return false
					}
				default:
					log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", v))
				}
			}
		case *rainslib.ShardSection:
			for _, val := range z.Content[i+1:] {
				switch val := val.(type) {
				case *rainslib.AssertionSection:
					if v.RangeFrom < val.SubjectName && v.RangeTo > val.SubjectName && !shardContainsAssertion(val, v) {
						log.Info("zone is internally not consistent. Zone contains an assertion which is not present in a shard in the range",
							"assertion", *val, "shard", *v)
						return false
					}
				case *rainslib.ShardSection:
					if val.RangeFrom < v.RangeTo && val.RangeTo > v.RangeFrom && !isShardConsistentWithShard(v, val) {
						log.Info("zone is internally not consistent. Zone contains a shard which is not consistent with another shard")
						return false
					}
				default:
					log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", v))
				}
			}
		default:
			log.Warn(fmt.Sprintf("Not supported type. Expected *ShardSection or *AssertionSection. Got=%T", v))
		}
	}
	return true
}

//addAssertionsinRangeToList adds all assertions from s which are in the range of interval to the returned sortedAssertions list
func addAssertionsinRangeToList(s *rainslib.ShardSection, interval rainslib.Interval, list *sortedAssertions) {
	for _, a := range s.Content {
		if a.SubjectName > interval.Begin() && a.SubjectName < interval.End() {
			list.Add(a)
		}
	}
}

type sortedAssertions struct {
	assertions     []*rainslib.AssertionSection
	assertionsLock sync.RWMutex
}

//Add adds the assertion to the sorted list at the correct position.
//It returns true if it added a and false if a is already contained
func (s *sortedAssertions) Add(a *rainslib.AssertionSection) bool {
	s.assertionsLock.Lock()
	defer s.assertionsLock.Unlock()
	i := sort.Search(len(s.assertions), func(i int) bool {
		return s.assertions[i].SubjectName >= a.SubjectName
	})
	if s.assertions[i].EqualContextZoneName(a) {
		return false
	}
	s.assertions = append(s.assertions[:i], append([]*rainslib.AssertionSection{a}, s.assertions[i:]...)...)
	return true
}

//Delete removes the assertion from the sorted list.
//Returns true if element was successfully deleted from the list. If a not part of list returns false
func (s *sortedAssertions) Delete(a *rainslib.AssertionSection) bool {
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
func (s *sortedAssertions) Get(interval rainslib.Interval) ([]*rainslib.AssertionSection, bool) {
	s.assertionsLock.RLock()
	defer s.assertionsLock.RUnlock()
	elements := []*rainslib.AssertionSection{}
	i := sort.Search(len(s.assertions), func(i int) bool {
		return s.assertions[i].SubjectName >= interval.Begin()
	})
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
