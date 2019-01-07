package cache

import (
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeHashMap"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

type pkcValue struct {
	//mss contains all the message and the sender for which some keys are missing
	mss util.MsgSectionSender
	//expiration contains the expiration value of the forwarded query
	expiration int64
}

type PendingKeyImpl struct {
	//tokenMap is a map from token to *pendingQueryCacheValue safe for concurrent use
	tokenMap *safeHashMap.Map
	//counter holds the number of sectionSender objects stored in the cache
	counter *safeCounter.Counter
}

func NewPendingKey(maxSize int) *PendingKeyImpl {
	return &PendingKeyImpl{
		tokenMap: safeHashMap.New(),
		counter:  safeCounter.New(maxSize),
	}
}

//Add adds ss to the cache together with the token and expiration time of the query sent to the
//host with the addr defined in ss.
func (c *PendingKeyImpl) Add(ss util.MsgSectionSender, t token.Token, expiration int64) {
	if c.counter.IsFull() {
		log.Error("Pending key cache is full")
		return
	}
	c.counter.Inc()
	if ok := c.tokenMap.Add(t.String(), pkcValue{mss: ss, expiration: expiration}); !ok {
		log.Warn("Token already in key cache. Random source of Token generator no random enough?")
	}
}

//GetAndRemove returns util.MsgSectionSender which corresponds to token and true, and deletes it from
//the cache. False is returned if no util.MsgSectionSender matched token.
func (c *PendingKeyImpl) GetAndRemove(t token.Token) (util.MsgSectionSender, bool) {
	if val, present := c.tokenMap.Get(t.String()); present {
		c.tokenMap.Remove(t.String())
		c.counter.Dec()
		return val.(pkcValue).mss, true
	}
	return util.MsgSectionSender{}, false
}

//ContainsToken returns true if t is cached
func (c *PendingKeyImpl) ContainsToken(t token.Token) bool {
	_, present := c.tokenMap.Get(t.String())
	return present
}

//RemoveExpiredValues deletes all expired entries. It logs the host's addr which was not able to
//respond in time.
func (c *PendingKeyImpl) RemoveExpiredValues() {
	keys := c.tokenMap.GetAllKeys()
	for _, key := range keys {
		if val, present := c.tokenMap.Get(key); present {
			if val := val.(pkcValue); val.expiration < time.Now().Unix() {
				c.tokenMap.Remove(key)
				c.counter.Dec()
				log.Warn("No response to delegation query received before expiration",
					"sectionSender", val.mss)
			}
		}
	}
}

//Len returns the number of sections in the cache
func (c *PendingKeyImpl) Len() int {
	return c.tokenMap.Len()
}
