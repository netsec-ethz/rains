package oldCaches

/*
 * assertion cache implementation
 * We have a hierarchical locking system. We first lock the cache to get a pointer to a set data structure. Then we release the lock on the cache and for
 * operations on the set data structure we use a separate lock.
 * We store the elementCount (number of sections in the pendingQueryCacheImpl) separate, as each cache entry can have several querier infos in the set data structure.
 * When we want to update elementCount we must lock using elemCountLock. This lock must never be held when doing a change to the the cache or the set data structure.
 * It can happen that some sections get dropped. This is the case when the cache is full or when we add a section to the set while another go routine deletes the pointer to that
 * set as it was empty before. The second case is expected to occur rarely.
 */
/*type assertionCacheImpl struct {
	//assertionCache stores to a given <context,zone,name,type> a set of assertions
	assertionCache *cache.Cache
	maxElements    uint
	elementCount   uint
	//elemCountLock protects elementCount from simultaneous access. It must not be locked during a modifying call to the cache or the set data structure.
	elemCountLock sync.RWMutex

	//rangeMap contains a map from context and zone to a sorted list according to the name of assertions which contains elemAndValidity.
	rangeMap     map[contextAndZone]*sortedAssertionMetaData
	rangeMapLock sync.RWMutex
}

//Add adds an assertion together with a validity to the cache.
//Returns true if cache did not already contain an entry for the given context,zone, name and objType
//If the cache is full it removes an external assertionCacheValue according to some metric.
func (c *assertionCacheImpl) Add(context, zone, name string, objType rainslib.ObjectType, internal bool, value assertionCacheValue) bool {
	set := setDataStruct.New()
	set.Add(value)
	ok := c.assertionCache.Add(set, internal, context, zone, name, objType.String())
	if ok {
		addAssertionToRangeMap(c, context, zone, name, objType, internal, value)
		updateAssertionCacheCount(c)
		handleAssertionCacheSize(c)
		return true
	}
	//there is already a set in the cache, get it and add value.
	v, ok := c.assertionCache.Get(context, zone, name, objType.String())
	if ok {
		set, ok := v.(setContainer)
		if ok {
			ok := set.Add(value)
			if ok {
				addAssertionToRangeMap(c, context, zone, name, objType, internal, value)
				updateAssertionCacheCount(c)
				handleAssertionCacheSize(c)
				log.Debug("Added assertion to cache.", "assertion", *value.section)
				return true
			}
			log.Warn("Set was closed but cache entry was not yet deleted. This case must be rare!")
			return false
		}
		log.Error(fmt.Sprintf("Cache element was not of type setContainer. Got:%T", v))
		return false
	}
	//cache entry was deleted in the meantime. Retry
	log.Warn("Cache entry was delete between, trying to add new and getting the existing one. This case must be rare!")
	return c.Add(context, zone, name, objType, internal, value)
}

func addAssertionToRangeMap(c *assertionCacheImpl, context, zone, name string, objType rainslib.ObjectType, internal bool, value assertionCacheValue) {
	c.rangeMapLock.Lock()
	elem := elemAndValidity{
		elemAndValidTo: elemAndValidTo{
			context:    context,
			zone:       zone,
			name:       name,
			objType:    objType,
			validUntil: value.validUntil},
		validSince: value.validSince,
	}
	if val, ok := c.rangeMap[contextAndZone{Context: context, Zone: zone}]; ok {
		c.rangeMapLock.Unlock()
		val.Add(elem)
	} else {
		c.rangeMap[contextAndZone{Context: context, Zone: zone}] = &sortedAssertionMetaData{assertions: []elemAndValidity{elem}}
		c.rangeMapLock.Unlock()
	}
}

//updateAssertionCacheCount increases the element count by one
func updateAssertionCacheCount(c *assertionCacheImpl) {
	c.elemCountLock.Lock()
	c.elementCount++
	c.elemCountLock.Unlock()
}

//handleAssertionCacheSize deletes all assertions from the least recently used cache entry if it exceeds the cache size
func handleAssertionCacheSize(c *assertionCacheImpl) {
	c.elemCountLock.RLock()
	if c.elementCount > c.maxElements {
		c.elemCountLock.RUnlock()
		key, _ := c.assertionCache.GetLeastRecentlyUsedKey()
		v, ok := c.assertionCache.Get(key[0], key[1])
		if ok {
			if set, ok := v.(setContainer); ok {
				vals := set.GetAllAndDelete()
				c.assertionCache.Remove(key[0], key[1])
				for _, val := range vals {
					val := val.(assertionCacheValue)
					deleteAssertionFromRangeMap(c, val.section, val.validSince, val.validUntil)
				}
			}
		}
	} else {
		c.elemCountLock.RUnlock()
	}
}

//deleteAssertionFromRangeMap deletes the given assertion from the rangeMap. Return true if it was able to delete the element
func deleteAssertionFromRangeMap(c *assertionCacheImpl, assertion *rainslib.AssertionSection, validSince, validUntil int64) bool {
	c.rangeMapLock.RLock()
	e, ok := c.rangeMap[contextAndZone{Context: assertion.Context, Zone: assertion.SubjectZone}]
	c.rangeMapLock.RUnlock()
	if ok { //if not ok, element was already removed and we are done.
		return e.Delete(elemAndValidity{
			elemAndValidTo: elemAndValidTo{
				context: assertion.Context,
				zone:    assertion.SubjectZone,
				name:    assertion.SubjectName,
				//FIXME CFE when assertion can contain several types. Delete all of them from
				objType:    assertion.Content[0].Type,
				validUntil: validUntil,
			},
			validSince: validSince,
		})
	}
	return false
}

//Get returns true and a set of assertions matching the given key if there exists some. Otherwise false is returned
//If expiredAllowed is false, then no expired assertions will be returned
func (c *assertionCacheImpl) Get(context, zone, name string, objType rainslib.ObjectType, expiredAllowed bool) ([]*rainslib.AssertionSection, bool) {
	assertions := []*rainslib.AssertionSection{}
	v, ok := c.assertionCache.Get(context, zone, name, objType.String())
	if ok {
		if set, ok := v.(setContainer); ok {
			for _, val := range set.GetAll() {
				if value, ok := val.(assertionCacheValue); ok {
					if value.validSince < time.Now().Unix() {
						if expiredAllowed || value.validUntil > time.Now().Unix() {
							assertions = append(assertions, value.section)
						}
					}
				} else {
					log.Error(fmt.Sprintf("Cache element was not of type assertionCacheValue. Got:%T", val))
				}
			}
			return assertions, true
		}
		log.Error(fmt.Sprintf("Cache element was not of type setContainer. Got:%T", v))
	}
	return nil, false
}

//GetInRange returns true and a set of valid assertions in the given interval matching the given context and zone if there are any. Otherwise false is returned
func (c *assertionCacheImpl) GetInRange(context, zone string, interval rainslib.Interval) ([]*rainslib.AssertionSection, bool) {
	c.rangeMapLock.RLock()
	sortedList, ok := c.rangeMap[contextAndZone{Context: context, Zone: zone}]
	c.rangeMapLock.RUnlock()
	if ok {
		assertionMetaInfos := sortedList.Get(interval)
		for _, elem := range assertionMetaInfos {
			if elem.validSince < time.Now().Unix() && elem.validUntil > time.Now().Unix() {
				if assertions, ok := c.Get(context, zone, elem.name, elem.objType, false); ok {
					return assertions, true
				}
			}
		}
	}
	return nil, false
}

//Len returns the number of elements in the cache.
func (c *assertionCacheImpl) Len() int {
	c.elemCountLock.RLock()
	defer c.elemCountLock.RUnlock()
	return int(c.elementCount)
}

//RemoveExpiredValues goes through the cache and removes all expired assertions. If for a given context and zone there is no assertion left it removes the entry from cache.
func (c *assertionCacheImpl) RemoveExpiredValues() {
	//Delete expired assertions, shards or zones
	keys := c.assertionCache.Keys()
	for _, key := range keys {
		deleteAssertions(c, false, key[0], key[1])
		updateAssertionCacheStructure(c, key[0], key[1])
	}
	updateAssertionCacheRangeMapping(c)
}

//deleteAssertions removes assertions from the cache and the rangeMap matching the given parameter. It does not update the cache structure.
//if forceDelete is true then all matching assertions are deleted. Otherwise only expired once.
//Returns the number of deleted elements
func deleteAssertions(c *assertionCacheImpl, forceDelete bool, context string, keys ...string) uint {
	deleteCount := uint(0)
	set, ok := getAssertionSet(c, context, keys...)
	if ok {
		vals := set.GetAll()
		//check validity of all container elements and remove expired once or all if forceDelete is set.
		for _, val := range vals {
			v, ok := val.(assertionCacheValue)
			if ok {
				if forceDelete || v.validUntil < time.Now().Unix() {
					ok := set.Delete(val)
					if ok {
						deleteCount++
						ok := deleteAssertionFromRangeMap(c, v.section, v.validSince, v.validUntil)
						if !ok {
							log.Error("Was not able to delete assertion from rangeMap", "assertion", v.section)
						}
					}
				}
			} else {
				log.Error(fmt.Sprintf("set element was not of type assertionCacheValue. Got:%T", val))
			}
		}
	}
	c.elemCountLock.Lock()
	c.elementCount -= deleteCount
	c.elemCountLock.Unlock()
	return deleteCount
}

//getAssertionSet return true and the set of assertions stored in the cache for the given context and keys=(zone,name,type) if present. Otherwise false is returned
func getAssertionSet(c *assertionCacheImpl, context string, keys ...string) (setContainer, bool) {
	v, ok := c.assertionCache.Get(context, keys...)
	if ok { //check if element is still contained
		set, ok := v.(setContainer)
		if ok {
			return set, true
		}
		log.Error(fmt.Sprintf("Cache element was not of type setContainer. Got:%T", v))
	}
	log.Debug("There is no set in the cache for the given context and keys.", "context", context, "keys", keys)
	return nil, false
}

//updateAssertionCacheStructure removes a cache entry if it points to a set without assertions.
func updateAssertionCacheStructure(c *assertionCacheImpl, context, keys string) {
	v, ok := c.assertionCache.Get(context, keys)
	if ok { //check if element is still contained
		set, ok := v.(setContainer)
		if ok { //check that cache element is a setContainer
			if set.Len() == 0 {
				vals := set.GetAllAndDelete()
				if len(vals) == 0 {
					c.assertionCache.Remove(context, keys)
				} else {
					set := setDataStruct.New()
					for _, val := range vals {
						set.Add(val)
					}
					//FIXME CFE here another go routine could come in between. Add an update function to the cache.
					//Right now we overwrite an internal set to an external. This is not the case if we update the value.
					c.assertionCache.Remove(context, keys)
					c.assertionCache.Add(set, false, context, keys)
				}
			}
		} else {
			log.Error(fmt.Sprintf("Cache element was not of type setContainer. Got:%T", v))
		}
	}
}

//updateAssertionCacheRangeMapping deletes all entries from the rangeMap which point to an empty slice
func updateAssertionCacheRangeMapping(c *assertionCacheImpl) {
	c.rangeMapLock.Lock()
	defer c.rangeMapLock.Unlock()
	for k, v := range c.rangeMap {
		if v.Len() == 0 {
			delete(c.rangeMap, k)
		}
	}
}

//Remove deletes the given assertion from the cache. Returns true if it was able to remove at least one assertion
func (c *assertionCacheImpl) Remove(assertion *rainslib.AssertionSection) bool {
	//CFE FIXME This does not work if we have several types per assertion
	return deleteAssertions(c, true, assertion.Context, assertion.SubjectZone, assertion.SubjectName, assertion.Content[0].Type.String()) > 0
}
*/
/*
 * negative assertion implementation
 * We have a hierarchical locking system. We first lock the cache to get a pointer to a data structure which can efficiently process range queries (e.g. interval tree).
 * Then we release the lock on the cache and for operations on the set data structure we use a separate lock.
 * We store the elementCount (number of sections in the negativeAssertionCacheImpl) separate, as each cache entry can have several sections in the data structure.
 * When we want to update elementCount we must lock using elemCountLock. This lock must never be held when doing a change to the the cache or the underlying data structure.
 * It can happen that some sections get dropped. This is the case when the cache is full or when we add a section to the set while another go routine deletes the pointer to that
 * set as it was empty before. The second case is expected to occur rarely.
 */
/*
type negativeAssertionCacheImpl struct {
	cache        *cache.Cache
	maxElements  uint
	elementCount uint
	//elemCountLock protects elementCount from simultaneous access. It must not be locked during a modifying call to the cache or the underlying data structure.
	elemCountLock sync.RWMutex
}

//Add adds a shard or zone together with a validity to the cache.
//Returns true if value was added to the cache.
//If the cache is full it removes an external negativeAssertionCacheValue according to some metric.
func (c *negativeAssertionCacheImpl) Add(context, zone string, internal bool, value negativeAssertionCacheValue) bool {
	//TODO add an getOrAdd method to the cache (locking must then be changed.)
	//TODO CFE replace sectionList with interval tree
	l := &sectionList{list: list.New()}
	l.Add(value)
	ok := c.cache.Add(l, internal, context, zone)
	if ok {
		updateNegElementCount(c)
		handleNegElementCacheSize(c)
		return true
	}
	//there is already a set in the cache, get it and add value.
	v, ok := c.cache.Get(context, zone)
	if ok {
		val, ok := v.(rangeQueryDataStruct)
		if ok {
			if ok := val.Add(value); ok {
				updateNegElementCount(c)
				handleNegElementCacheSize(c)
				return true
			}
			return false //element is already contained
		}
		log.Error(fmt.Sprintf("Cache entry is not of type rangeQueryDataStruct. Got=%T", v))
		return false
	}
	//cache entry was deleted in the meantime. Retry
	log.Warn("Cache entry was delete between, trying to add new and getting the existing one. This case must be rare!")
	return c.Add(context, zone, internal, value)
}

//updateNegElementCount increases the element count by one
func updateNegElementCount(c *negativeAssertionCacheImpl) {
	c.elemCountLock.Lock()
	c.elementCount++
	c.elemCountLock.Unlock()
}

//handleNegElementCacheSize  deletes all intervals from the least recently used cache entry if it exceeds the cache size
func handleNegElementCacheSize(c *negativeAssertionCacheImpl) {
	if c.elementCount > c.maxElements {
		key, _ := c.cache.GetLeastRecentlyUsedKey()
		v, ok := c.cache.Get(key[0], key[1])
		if ok {
			//FIXME CFE another go routine might also have a pointer to the data structure behind this entry. Then the count might be off...
			c.cache.Remove(key[0], key[1])
			v, _ := v.(rangeQueryDataStruct).Get(rainslib.TotalInterval{})
			c.elemCountLock.Lock()
			c.elementCount -= uint(len(v))
			c.elemCountLock.Unlock()
		}
	}
}

//Get returns true and the shortest sections with the longest validity of a given context and zone containing the name if there exists one. Otherwise false is returned
func (c *negativeAssertionCacheImpl) Get(context, zone string, interval rainslib.Interval) (rainslib.MessageSectionWithSig, bool) {
	sections, ok := c.GetAll(context, zone, interval)
	if ok {
		//TODO CFE return shortest shard, how to find out how large a shard is, store number of assertions to it?
		//TODO CFE check in shortest shard: if interval.Begin() == interval.End() -> if assertion is contained and if so return assertion.
		//(could have been evicted from assertionsCache)
		return sections[0], true
	}
	return nil, false
}

//GetAll returns true and all sections of a given context and zone which intersect with the given Range if there is at least one. Otherwise false is returned
//if beginRange and endRange are an empty string then the zone and all shards of that context and zone are returned
func (c *negativeAssertionCacheImpl) GetAll(context, zone string, interval rainslib.Interval) ([]rainslib.MessageSectionWithSig, bool) {
	v, ok := c.cache.Get(context, zone)
	if !ok {
		return nil, false
	}
	if rq, ok := v.(rangeQueryDataStruct); ok {
		sections := []rainslib.MessageSectionWithSig{}
		if intervals, ok := rq.Get(interval); ok && len(intervals) > 0 {
			for _, element := range intervals {
				if val, ok := element.(negativeAssertionCacheValue); ok && val.validUntil > time.Now().Unix() && val.validSince < time.Now().Unix() {
					sections = append(sections, val.section)
				}
			}
			return sections, true
		}
		return nil, false
	}
	log.Error(fmt.Sprintf("Cache entry is not of type rangeQueryDataStruct. got=%T", v))
	return nil, false
}

//Len returns the number of elements in the cache.
func (c *negativeAssertionCacheImpl) Len() int {
	c.elemCountLock.RLock()
	defer c.elemCountLock.RUnlock()
	return int(c.elementCount)
}

//RemoveExpiredValues goes through the cache and removes all expired values. If for a given context and zone there is no value left it removes the entry from cache.
func (c *negativeAssertionCacheImpl) RemoveExpiredValues() {
	keys := c.cache.Keys()
	deleteCount := uint(0)
	for _, key := range keys {
		v, ok := c.cache.Get(key[0], key[1])
		if ok { //check if element is still contained
			rq, ok := v.(rangeQueryDataStruct)
			if ok { //check that cache element is a range query data structure
				vals, ok := rq.Get(rainslib.TotalInterval{})
				allRemoved := true
				if ok {
					//check validity of all contained elements and remove expired once
					for _, val := range vals {
						v, ok := val.(negativeAssertionCacheValue)
						if ok {
							if v.validUntil < time.Now().Unix() {
								ok := rq.Delete(val)
								if ok {
									deleteCount++
								}
							} else {
								allRemoved = false
							}
						} else {
							log.Error(fmt.Sprintf("set element was not of type negativeAssertionCacheValue. Got:%T", val))
						}
					}
				}
				//remove entry from cache if non left. If one was added in the meantime do not delete it.
				if allRemoved {
					c.cache.Remove(key[0], key[1])
				}
			} else {
				log.Error(fmt.Sprintf("Cache element was not of type rangeQueryDataStruct. Got:%T", v))
			}
		}
	}
	c.elemCountLock.Lock()
	c.elementCount -= deleteCount
	c.elemCountLock.Unlock()
}

//Remove deletes the cache entry for context and zone. Returns true if it was able to delete the entry
func (c *negativeAssertionCacheImpl) Remove(context, zone string) bool {
	v, ok := c.cache.Get(context, zone)
	c.cache.Remove(context, zone)
	if ok { //check if element is still contained
		rq, ok := v.(rangeQueryDataStruct)
		if ok {
			c.elemCountLock.Lock()
			c.elementCount -= uint(rq.Len())
			c.elemCountLock.Unlock()
		} else {
			log.Error(fmt.Sprintf("Cache element was not of type rangeQueryDataStruct. Got:%T", v))
		}
	}
	return true
}

type sectionList struct {
	list     *list.List
	listLock sync.RWMutex
}

//Add inserts item into the data structure
func (l *sectionList) Add(item rainslib.Interval) bool {
	l.listLock.Lock()
	defer l.listLock.Unlock()
	for e := l.list.Front(); e != nil; e = e.Next() {
		if e.Value == item {
			return false
		}
	}
	l.list.PushBack(item)
	return true
}

//Delete deletes item from the data structure
func (l *sectionList) Delete(item rainslib.Interval) bool {
	l.listLock.Lock()
	defer l.listLock.Unlock()
	for e := l.list.Front(); e != nil; e = e.Next() {
		if e.Value == item {
			l.list.Remove(e)
			return true
		}
	}
	return false
}

//Get returns true and all intervals which intersect with item if there are any. Otherwise false is returned
func (l *sectionList) Get(item rainslib.Interval) ([]rainslib.Interval, bool) {
	intervals := []rainslib.Interval{}
	l.listLock.RLock()
	defer l.listLock.RUnlock()
	for e := l.list.Front(); e != nil; e = e.Next() {
		val := e.Value.(rainslib.Interval)
		if val.Begin() < item.End() || val.End() > item.Begin() {
			intervals = append(intervals, val)
		}
	}
	return intervals, len(intervals) > 0
}

//returns the number of elements in the data structure
func (l *sectionList) Len() int {
	l.listLock.RLock()
	defer l.listLock.RUnlock()
	return l.list.Len()
}

type elemAndValidity struct {
	elemAndValidTo
	validSince int64
}

type sortedAssertionMetaData struct {
	assertions     []elemAndValidity
	assertionsLock sync.RWMutex
}

//Add adds e to the sorted list at the correct position.
//It returns true if it added e and false if e is already contained
func (s *sortedAssertionMetaData) Add(e elemAndValidity) bool {
	s.assertionsLock.Lock()
	defer s.assertionsLock.Unlock()
	i := sort.Search(len(s.assertions), func(i int) bool {
		return s.assertions[i].name >= e.name
	})
	if i == len(s.assertions) {
		s.assertions = append(s.assertions, e)
		return true
	}
	if s.assertions[i] == e {
		return false
	}
	s.assertions = append(s.assertions[:i], append([]elemAndValidity{e}, s.assertions[i:]...)...)
	return true
}

//Delete removes e from the sorted list.
//Returns true if element was successfully deleted from the list. If e not part of list returns false
func (s *sortedAssertionMetaData) Delete(e elemAndValidity) bool {
	s.assertionsLock.Lock()
	defer s.assertionsLock.Unlock()
	i := sort.Search(len(s.assertions), func(i int) bool {
		return s.assertions[i].name >= e.name
	})
	if s.assertions[i] != e {
		return false
	}
	s.assertions = append(s.assertions[:i], s.assertions[i+1:]...)
	return true
}

//Len returns the number of element in this sorted slice
func (s *sortedAssertionMetaData) Len() int {
	s.assertionsLock.RLock()
	defer s.assertionsLock.RUnlock()
	return len(s.assertions)
}

//Get returns all assertion meta data which are in the given interval
func (s *sortedAssertionMetaData) Get(interval rainslib.Interval) []elemAndValidity {
	s.assertionsLock.RLock()
	defer s.assertionsLock.RUnlock()
	elements := []elemAndValidity{}
	i := sort.Search(len(s.assertions), func(i int) bool {
		return s.assertions[i].name >= interval.Begin()
	})
	if s.assertions[i].name < interval.Begin() {
		return elements
	}
	for ; i < len(s.assertions); i++ {
		if s.assertions[i].name > interval.End() {
			break
		}
		elements = append(elements, s.assertions[i])
	}
	return elements
}*/

/*type negAssertionLRUCacheValue struct {
	ctxMap  *safeHashMap.Map //context -> *list.List
	deleted bool
	zone    string
	//mux protects deleted from simultaneous access.
	mux sync.RWMutex
}

//assertionCacheValue is the value stored in the assertionCacheImpl.cache
type negAssertionCacheValue struct {
	sections map[string]sectionExpiration //section.Hash -> sectionExpiration
	context  string
	deleted  bool
	//mux protects deleted and sections from simultaneous access.
	mux sync.RWMutex
}

type sectionExpiration struct {
	section    rainslib.MessageSectionWithSigForward
	expiration int64
}

type lruValue struct {
	internal bool
	zone     string
	value    *negAssertionCacheValue
}
*/
/*
 * negative assertion cache implementation
 * It keeps track of all assertionCacheValues of a zone in zoneMap (besides the cache)
 * such that we can remove all entries of a zone in case of misbehavior or inconsistencies.
 */ /*
type negativeAssertionCacheImpl struct {
	zoneMap *safeHashMap.Map //zone -> *negAssertionLRUCacheValue
	counter *safeCounter.Counter

	internalList *list.List //values in the internalList are only explicitly removed
	lruList      *list.List
}

//Add adds shard together with an expiration time (number of seconds since 01.01.1970) to
//the cache. It returns false if the cache is full and a non internal element has been removed
//according to some strategy.
func (c *negativeAssertionCacheImpl) AddShard(shard *rainslib.ShardSection, expiration int64, isInternal bool) bool {
	return add(c, shard, expiration, isInternal)
}

//Add adds zone together with an expiration time (number of seconds since 01.01.1970) to
//the cache. It returns false if the cache is full and a non internal element has been removed
//according to some strategy.
func (c *negativeAssertionCacheImpl) AddZone(zone *rainslib.ZoneSection, expiration int64, isInternal bool) bool {
	return add(c, zone, expiration, isInternal)
}

//add adds section together with an expiration time (number of seconds since 01.01.1970) to
//the cache. It returns false if the cache is full and an element was removed according to least
//recently used strategy.
func add(c *negativeAssertionCacheImpl, section rainslib.MessageSectionWithSigForward, expiration int64, isInternal bool) bool {
	isFull := false
	cacheLRUValue := negAssertionLRUCacheValue{ctxMap: safeHashMap.New(), zone: section.GetSubjectZone()}
	v, _ := c.zoneMap.GetOrAdd(section.GetSubjectZone(), &cacheLRUValue)
	value := v.(*negAssertionLRUCacheValue)
	value.mux.Lock()
	if value.deleted {
		value.mux.Unlock()
		return add(c, section, expiration, isInternal)
	}
	e, ok := value.ctxMap.Get(section.GetContext())
	if ok {
		if e == nil {
			log.Error("A list element returned by the hash map is nil. This should never occur!")
		}
		v := e.(*list.Element).Value.(*lruValue)
		if v.internal {
			c.internalList.MoveToFront(e.(*list.Element))
		} else {
			c.lruList.MoveToFront(e.(*list.Element))
		}
		value.mux.Unlock()
		v.value.mux.Lock()
		if v.value.deleted {
			v.value.mux.Unlock()
			return add(c, section, expiration, isInternal)
		}
		if _, ok := v.value.sections[section.Hash()]; !ok {
			v.value.sections[section.Hash()] = sectionExpiration{section: section, expiration: expiration}
			isFull = c.counter.Inc()
		}
		v.value.mux.Unlock()
	} else {
		cacheValue := &negAssertionCacheValue{
			sections: make(map[string]sectionExpiration),
			context:  section.GetContext(),
		}
		var elem *list.Element
		if isInternal {
			elem = c.internalList.PushFront(&lruValue{internal: true, zone: section.GetSubjectZone(), value: cacheValue})
		} else {
			elem = c.lruList.PushFront(&lruValue{internal: false, zone: section.GetSubjectZone(), value: cacheValue})
		}
		value.ctxMap.Add(section.GetContext(), elem)
		value.mux.Unlock()
		cacheValue.mux.Lock()
		if cacheValue.deleted {
			cacheValue.mux.Unlock()
			return add(c, section, expiration, isInternal)
		}
		if _, ok := cacheValue.sections[section.Hash()]; !ok {
			cacheValue.sections[section.Hash()] = sectionExpiration{section: section, expiration: expiration}
			isFull = c.counter.Inc()
		}
		cacheValue.mux.Unlock()
	}
	//Remove elements according to lru strategy
	//FIXME CFE add assertion to consistency cache
	//FIXME CFE must check that it is still reachable after insert because a delete operation might have happend simultaneously. while holding the lock all the time
	return !isFull
}

//Get returns true and a set of shards and zones matching subjectZone and context and overlap with
//interval if there exist some. When context is the empty string, a random context is chosen.
//Otherwise nil and false is returned.
func (c *negativeAssertionCacheImpl) Get(subjectZone, context string, interval rainslib.Interval) ([]rainslib.MessageSectionWithSigForward, bool) {
	v, ok := c.zoneMap.Get(subjectZone)
	if !ok {
		return nil, false
	}
	ctxMap := v.(*negAssertionLRUCacheValue)
	ctxMap.mux.RLock()
	if ctxMap.deleted {
		ctxMap.mux.RUnlock()
		return nil, false
	}
	var value *negAssertionCacheValue
	if context != "" {
		values := ctxMap.ctxMap.GetAll()
		if len(values) == 0 {
			ctxMap.mux.RUnlock()
			return nil, false
		}
		value = values[0].(*negAssertionCacheValue) //a random context
	} else {
		val, ok := ctxMap.ctxMap.Get(context)
		if !ok {
			ctxMap.mux.RUnlock()
			return nil, false
		}
		value = val.(*negAssertionCacheValue)
	}
	ctxMap.mux.RUnlock()
	value.mux.RLock()
	defer value.mux.RUnlock()
	if value.deleted {
		return nil, false
	}
	var sections []rainslib.MessageSectionWithSigForward
	for _, sec := range value.sections {
		if sec.section.Begin() < interval.End() && sec.section.End() > interval.Begin() {
			sections = append(sections, sec.section)
		}
	}
	return sections, len(sections) > 0
}

//RemoveExpiredValues goes through the cache and removes all expired assertions.
func (c *negativeAssertionCacheImpl) RemoveExpiredValues() {
	for _, v := range c.zoneMap.GetAll() {
		ctxMap := v.(*negAssertionLRUCacheValue)
		ctxMap.mux.RLock()
		if ctxMap.deleted {
			ctxMap.mux.RUnlock()
			continue
		}
		sections := ctxMap.ctxMap.GetAll()
		ctxMap.mux.RUnlock()
		for _, val := range sections {
			deleteCount := 0
			value := val.(*negAssertionCacheValue)
			//TODO CFE this lock might be kept too long. use readlock and only if we want to remove
			//an entry obtain write lock?
			value.mux.Lock()
			if value.deleted {
				value.mux.Unlock()
				continue
			}
			for key, section := range value.sections {
				if section.expiration < time.Now().Unix() {
					delete(value.sections, key)
					deleteCount++
				}
			}
			if len(value.sections) == 0 {
				value.deleted = true
				ctxMap.ctxMap.Remove(value.context)
			}
			value.mux.Unlock()
			c.counter.Sub(deleteCount)
		}
		ctxMap.mux.Lock()
		if ctxMap.deleted || ctxMap.ctxMap.Len() > 0 {
			ctxMap.mux.Unlock()
			continue
		}
		ctxMap.deleted = true
		c.zoneMap.Remove(ctxMap.zone)
		ctxMap.mux.Unlock()

	}
	//FIXME CFE remove assertion from consistency cache
}

//RemoveZone deletes all assertions in the cache of the given zone.
func (c *negativeAssertionCacheImpl) RemoveZone(subjectZone string) {
	if v, ok := c.zoneMap.Remove(subjectZone); ok {
		ctxMap := v.(*negAssertionLRUCacheValue)
		ctxMap.mux.Lock()
		if ctxMap.deleted {
			ctxMap.mux.Unlock()
			return
		}
		ctxMap.deleted = true
		sections := ctxMap.ctxMap.GetAll()
		ctxMap.mux.Unlock()
		for _, val := range sections {
			value := val.(*negAssertionCacheValue)
			value.mux.Lock()
			if value.deleted {
				value.mux.Unlock()
				continue
			}
			value.deleted = true
			c.counter.Sub(len(value.sections))
			value.mux.Unlock()
		}
	}
	//FIXME CFE remove assertion from consistency cache
}

//Len returns the number of elements in the cache.
func (c *negativeAssertionCacheImpl) Len() int {
	return c.counter.Value()
}*/
