package rainsd

/*type pendingKeyCacheValue struct {
	mux sync.Mutex
	//sections is a hash map from algoType and phase to a hash map keyed by section.Hash and
	//pointing to util.SectionWithSigSender in which section is contained
	sections map[string]map[string]util.SectionWithSigSender
	//zoneCtx is zoneCtxMap's key
	zoneCtx string
	//token is tokenMap's key
	token token.Token
	//sendTo is the connection information of the server to which the delegation query has been sent
	sendTo connection.Info
	//expiration is the time when the delegation query expires in unix time
	expiration int64
	//set to true if the pointer to this element is removed from both hash maps
	deleted bool
}



func algoPhaseKey(algoType algorithmTypes.Signature, phase int) string {
	return fmt.Sprintf("%s %d", algoType, phase)
}

type pendingKeyCacheImpl struct {
	//zoneCtxMap is a map from zoneContext to *pendingKeyCacheValue safe for concurrent use
	zoneCtxMap *safeHashMap.Map
	//tokenMap is a map from token to *pendingKeyCacheValue safe for concurrent use
	tokenMap *safeHashMap.Map

	counter *safeCounter.Counter
}

//Add adds sectionSender to the cache and returns true if a new delegation should be sent.
func (c *pendingKeyCacheImpl) Add(sectionSender util.MsgSectionSender,
	algoType algorithmTypes.Signature, phase int) bool {
	if c.counter.Inc() {
		log.Warn("pending key cache is full", "size", c.counter.Value())
		c.counter.Dec()
		return false
	}
	section := sectionSender.Sections[0]
	entry := &pendingKeyCacheValue{
		zoneCtx:    zoneCtxKey(section.GetSubjectZone(), section.GetContext()),
		sections:   make(map[string]map[string]util.SectionWithSigSender),
		expiration: time.Now().Add(time.Second).Unix(),
	}
	newSet := make(map[string]util.SectionWithSigSender)
	newSet[section.Hash()] = sectionSender
	entry.sections[algoPhaseKey(algoType, phase)] = newSet
	if entry, ok := c.zoneCtxMap.GetOrAdd(entry.zoneCtx, entry); !ok {
		value := entry.(*pendingKeyCacheValue)
		value.mux.Lock()
		if value.deleted {
			value.mux.Unlock()
			return c.Add(sectionSender, algoType, phase)
		}
		defer value.mux.Unlock()
		if set, ok := value.sections[algoPhaseKey(algoType, phase)]; !ok {
			value.sections[algoPhaseKey(algoType, phase)] = newSet
		} else {
			if _, ok := set[section.Hash()]; !ok {
				set[section.Hash()] = sectionSender
			} else {
				c.counter.Dec()
			}
		}
		isExpired := value.expiration < time.Now().Unix()
		if isExpired {
			value.expiration = time.Now().Add(time.Second).Unix()
			log.Warn("pending key cache entry has expired", "value", value)
		}
		return isExpired
	}
	return true
}

//AddToken adds token to the token map where the value of the map corresponds to the cache entry
//matching the given zone and context. Token is only added to the map if a matching cache entry
//exists without a token. True is returned if the entry is updated.
func (c *pendingKeyCacheImpl) AddToken(token token.Token, expiration int64,
	sendTo connection.Info, zone, context string) bool {
	if entry, ok := c.zoneCtxMap.Get(zoneCtxKey(zone, context)); ok {
		value := entry.(*pendingKeyCacheValue)
		value.mux.Lock()
		defer value.mux.Unlock()
		if value.token == [16]byte{} {
			if _, ok := c.tokenMap.GetOrAdd(token.String(), value); !ok {
				log.Error("token already in cache. Token was reused too early", "token", token)
				return false
			}
			value.token = token
			value.expiration = expiration
			value.sendTo = sendTo
			return true
		}
	}
	return false
}

//GetAndRemove returns all sections who contain a signature matching the given parameter and
//deletes them from the cache. It returns true if at least one section is returned. The token
//map is updated if necessary.
func (c *pendingKeyCacheImpl) GetAndRemove(zone, context string, algoType algorithmTypes.Signature, phase int) []util.SectionWithSigSender {
	if entry, ok := c.zoneCtxMap.Get(zoneCtxKey(zone, context)); ok {
		value := entry.(*pendingKeyCacheValue)
		value.mux.Lock()
		defer value.mux.Unlock()
		if value.deleted {
			return nil
		}
		if set, ok := value.sections[algoPhaseKey(algoType, phase)]; ok {
			if len(value.sections) == 1 {
				value.deleted = true
				e, _ := c.zoneCtxMap.Remove(zoneCtxKey(zone, context))
				c.tokenMap.Remove(e.(*pendingKeyCacheValue).token.String())
			}
			sectionSenders := []util.SectionWithSigSender{}
			for _, v := range set {
				sectionSenders = append(sectionSenders, v)
			}
			delete(value.sections, algoPhaseKey(algoType, phase))
			c.counter.Sub(len(sectionSenders))
			return sectionSenders
		}
	}
	return nil
}

//GetAndRemoveByToken returns all sections who correspond to token and deletes them from the
//cache. It returns true if at least one section is returned. Token is removed from the token
//map.
func (c *pendingKeyCacheImpl) GetAndRemoveByToken(token token.Token) []util.SectionWithSigSender {
	if entry, ok := c.tokenMap.Remove(token.String()); ok {
		value := entry.(*pendingKeyCacheValue)
		value.mux.Lock()
		if value.deleted {
			value.mux.Unlock()
			return nil
		}
		value.deleted = true
		c.zoneCtxMap.Remove(value.zoneCtx)
		value.mux.Unlock()
		sectionSenders := []util.SectionWithSigSender{}
		for _, set := range value.sections {
			for _, sectionSender := range set {
				sectionSenders = append(sectionSenders, sectionSender)
			}
		}
		c.counter.Sub(len(sectionSenders))
		return sectionSenders
	}
	return nil
}

//ContainsToken returns true if token is in the token map.
func (c *pendingKeyCacheImpl) ContainsToken(token token.Token) bool {
	_, ok := c.tokenMap.Get(token.String())
	return ok
}

//RemoveExpiredValues deletes all sections of an expired entry and updates the token map if
//necessary. It logs which sections are removed and to which server the query has been sent.
func (c *pendingKeyCacheImpl) RemoveExpiredValues() {
	for _, value := range c.zoneCtxMap.GetAll() {
		v := value.(*pendingKeyCacheValue)
		v.mux.Lock()
		if v.deleted {
			v.mux.Unlock()
			continue
		}
		if v.expiration < time.Now().Unix() {
			v.deleted = true
			c.tokenMap.Remove(v.token.String())
			c.zoneCtxMap.Remove(v.zoneCtx)
			log.Warn("pending key cache entry has expired", "value", v)
			for _, set := range v.sections {
				c.counter.Sub(len(set))
			}
		}
		v.mux.Unlock()
	}
}

//Len returns the number of sections in the cache
func (c *pendingKeyCacheImpl) Len() int {
	return c.counter.Value()
}

type pendingQueryCacheValue struct {
	mux sync.Mutex
	//queries contains all queries waiting for an answer to a query that has been sent by this server.
	queries []util.MsgSectionSender
	//nameCtxTypes is nameCtxTypesMap's key
	nameCtxTypes string
	//token is tokenMap's key
	token token.Token
	//sendTo is the connection information of the server to which the delegation query has been sent
	sendTo connection.Info
	//expiration is the time when the delegation query expires in unix time
	expiration int64
	//set to true if the pointer to this element is removed from both hash maps
	deleted bool
	//answers is a set of sections answering the pending queries (implemented as a map from
	//section.Hash() to section)
	answers *safeHashMap.Map
	//deadline is a timestamp when a response containing answers is sent to all pending queries. It
	//is measured as the number of nanoseconds passed since 1.1.1970 (unix time in nanoseconds).
	deadline int64
}

func nameCtxTypesKey(zone, context string, types []object.Type) string {
	if types == nil {
		return fmt.Sprintf("%s %s nil", zone, context)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	return fmt.Sprintf("%s %s %v", zone, context, types)
}

//TODO CFE this cache is currently not able to return all queries based on an assertion's name,
//context and type. This can be achieved by adding a safeHashMap keyed by name, context and type
//pointing to a set of *pendingQueryCacheValue
type pendingQueryCacheImpl struct {
	//zoneCtxMap is a map from zoneContext to *pendingQueryCacheValue safe for concurrent use
	nameCtxTypesMap *safeHashMap.Map
	//tokenMap is a map from token to *pendingQueryCacheValue safe for concurrent use
	tokenMap *safeHashMap.Map
	//counter holds the number of queries stored in the cache
	counter *safeCounter.Counter
}

//Add adds sectionSender to the cache and returns false if the query is already in the cache.
func (c *pendingQueryCacheImpl) Add(sectionSender util.MsgSectionSender) bool {
	if c.counter.Inc() {
		log.Warn("pending query cache is full", "size", c.counter.Value())
		c.counter.Dec()
		return false
	}
	query := sectionSender.Section.(*query.Name)
	entry := &pendingQueryCacheValue{
		nameCtxTypes: nameCtxTypesKey(query.Name, query.Context, query.Types),
		queries:      []util.MsgSectionSender{sectionSender},
		answers:      safeHashMap.New(),
		expiration:   time.Now().Add(time.Second).Unix(),
	}
	if entry, ok := c.nameCtxTypesMap.GetOrAdd(entry.nameCtxTypes, entry); !ok {
		value := entry.(*pendingQueryCacheValue)
		value.mux.Lock()
		if value.deleted {
			value.mux.Unlock()
			return c.Add(sectionSender)
		}
		defer value.mux.Unlock()
		value.queries = append(value.queries, sectionSender)
		isExpired := value.expiration < time.Now().Unix()
		if isExpired {
			value.expiration = time.Now().Add(time.Second).Unix()
			log.Warn("pending query cache entry has expired", "value", value)
		}
		return isExpired
	}
	return true
}

//AddToken adds token to the token map where the value of the map corresponds to the cache entry
//matching the given (fully qualified) name, context and connection (sorted). Token is added to the map
//and the cache entry's token, expiration and sendTo fields are updated only if a matching cache
//entry exists. True is returned if the entry is updated.
func (c *pendingQueryCacheImpl) AddToken(token token.Token, expiration int64,
	sendTo connection.Info, name, context string, types []object.Type) bool {
	if entry, ok := c.nameCtxTypesMap.Get(nameCtxTypesKey(name, context, types)); ok {
		value := entry.(*pendingQueryCacheValue)
		value.mux.Lock()
		defer value.mux.Unlock()
		if value.token == [16]byte{} {
			if _, ok := c.tokenMap.GetOrAdd(token.String(), value); !ok {
				log.Error("token already in cache. Token was reused too early", "token", token)
				return false
			}
			value.token = token
			value.expiration = expiration
			value.sendTo = sendTo
			return true
		}
	}
	return false
}

//GetQuery returns true and the query stored with token in the cache if there is such an entry.
func (c *pendingQueryCacheImpl) GetQuery(token token.Token) (section.Section, bool) {
	if entry, ok := c.tokenMap.Get(token.String()); ok {
		v := entry.(*pendingQueryCacheValue)
		v.mux.Lock()
		defer v.mux.Unlock()
		if !v.deleted {
			return v.queries[0].Section, true
		}
	}
	return nil, false
}

//AddAnswerByToken adds section to the cache entry matching token with the given deadline. It
//returns a pending query from the entry and true if there is a matching token in the cache and
//section is not already stored for these pending queries. The pending queries are are not removed
//from the cache.
func (c *pendingQueryCacheImpl) AddAnswerByToken(section section.WithSig,
	token token.Token, deadline int64) bool {
	if entry, ok := c.tokenMap.Get(token.String()); ok {
		v := entry.(*pendingQueryCacheValue)
		v.mux.Lock()
		defer v.mux.Unlock()
		if !v.deleted {
			v.deadline = deadline
			if _, ok := v.answers.GetOrAdd(section.Hash(), section); ok {
				return true
			}
		}
	}
	return false
}

//GetAndRemoveByToken returns all queries waiting for a response to a query message containing
//token and deletes them from the cache if no other section has been added to this cache entry
//since section has been added by AddAnswerByToken(). Token is removed from the token map.
func (c *pendingQueryCacheImpl) GetAndRemoveByToken(token token.Token, deadline int64) (
	[]util.MsgSectionSender, []section.Section) {
	if entry, ok := c.tokenMap.Get(token.String()); ok {
		v := entry.(*pendingQueryCacheValue)
		v.mux.Lock()
		defer v.mux.Unlock()
		if v.deleted || v.deadline != deadline {
			return nil, nil
		}
		v.deleted = true
		c.tokenMap.Remove(token.String())
		c.nameCtxTypesMap.Remove(v.nameCtxTypes)
		c.counter.Sub(len(v.queries))
		var answers []section.Section
		for _, sec := range v.answers.GetAll() {
			answers = append(answers, sec.(section.Section))
		}
		return v.queries, answers
	}
	return nil, nil
}

//UpdateToken adds newToken to the token map, lets it point to the cache value pointed by
//oldToken and removes oldToken from the token map if newToken is not already in the token map.
//It returns false if there is already an entry for newToken in the token map.
func (c *pendingQueryCacheImpl) UpdateToken(oldToken, newToken token.Token) bool {
	if v, ok := c.tokenMap.Get(oldToken.String()); ok {
		value := v.(*pendingQueryCacheValue)
		value.mux.Lock()
		defer value.mux.Unlock()
		if value.deleted {
			return true
		}
		if _, ok := c.tokenMap.GetOrAdd(newToken.String(), value); ok {
			c.tokenMap.Remove(oldToken.String())
			return true
		}
		return false
	}
	return true
}

//RemoveExpiredValues deletes all queries of an expired entry and updates the token map if
//necessary. It logs which queries are removed and from which server the query has come and to
//which it has been sent.
func (c *pendingQueryCacheImpl) RemoveExpiredValues() {
	for _, value := range c.nameCtxTypesMap.GetAll() {
		v := value.(*pendingQueryCacheValue)
		v.mux.Lock()
		if v.deleted {
			v.mux.Unlock()
			continue
		}
		if v.expiration < time.Now().Unix() {
			v.deleted = true
			c.tokenMap.Remove(v.token.String())
			c.nameCtxTypesMap.Remove(v.nameCtxTypes)
			log.Warn("pending query cache entry has expired", "value", v)
			c.counter.Sub(len(v.queries))
		}
		v.mux.Unlock()
	}
}

//Len returns the number of queries in the cache
func (c *pendingQueryCacheImpl) Len() int {
	return c.counter.Value()
}*/
