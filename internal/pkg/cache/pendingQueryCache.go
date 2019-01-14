package cache

import (
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/datastructures/safeCounter"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
)

//pqcValue contains sectionSender objets waiting for a query answer to arrive until expiration.
type pqcValue struct {
	sss        []util.MsgSectionSender
	expiration int64
}

//pqcKey returns a unique string representation of sections. Sections MUST only contain queries
func pqcKey(sections []section.Section) (string, error) {
	result := []string{}
	for _, q := range sections {
		q, ok := q.(*query.Name)
		if !ok {
			return "", fmt.Errorf("sections MUST only contain queries. sections=%v", sections)
		}
		for _, t := range q.Types {
			if t == object.OTDelegation {
				result = append(result, fmt.Sprintf("%s:%s:%d:%d", q.Name, q.Context, q.Types, q.KeyPhase))
			} else {
				result = append(result, fmt.Sprintf("%s:%s:%d", q.Name, q.Context, q.Types))
			}
		}
	}
	return strings.Join(result, "::"), nil
}

type PendingQueryImpl struct {
	qmux     sync.Mutex
	queryMap map[string]token.Token

	tmux     sync.Mutex
	tokenMap map[token.Token]*pqcValue

	//counter holds the number of sectionSender objects stored in the cache
	counter *safeCounter.Counter
}

func NewPendingQuery(maxSize int) *PendingQueryImpl {
	return &PendingQueryImpl{
		queryMap: make(map[string]token.Token),
		tokenMap: make(map[token.Token]*pqcValue),
		counter:  safeCounter.New(maxSize),
	}
}

//Add checks if this server has already forwarded a msg containing the same queries as ss. If
//this is the case, ss is added to the cache and false is returned. If not, ss is added together
//with t and expiration to the cache and true is returned.
func (c *PendingQueryImpl) Add(ss util.MsgSectionSender, t token.Token, expiration int64) bool {
	c.qmux.Lock()
	c.tmux.Lock()
	defer c.tmux.Unlock()

	if c.counter.IsFull() {
		c.qmux.Unlock()
		log.Error("Pending query cache is full")
		return false
	}
	qmKey, err := pqcKey(ss.Sections)
	if err != nil {
		c.qmux.Unlock()
		return false
	}
	c.counter.Inc()
	if t, present := c.queryMap[qmKey]; present && c.tokenMap[t].expiration > time.Now().Unix() {
		c.qmux.Unlock()
		val := c.tokenMap[t]
		val.sss = append(val.sss, ss)
		return false
	}
	c.queryMap[qmKey] = t
	c.qmux.Unlock()
	c.tokenMap[t] = &pqcValue{sss: []util.MsgSectionSender{ss}, expiration: expiration}
	return true
}

//GetAndRemove returns all util.MsgSectionSenders which correspond to token and delete them from the
//cache.
func (c *PendingQueryImpl) GetAndRemove(t token.Token) []util.MsgSectionSender {
	c.qmux.Lock()
	c.tmux.Lock()
	defer c.qmux.Unlock()
	defer c.tmux.Unlock()

	if val, present := c.tokenMap[t]; present {
		delete(c.tokenMap, t)
		key, _ := pqcKey(val.sss[0].Sections) //error case is catched in Add method.
		delete(c.queryMap, key)               //all sss have the same pqcKey
		c.counter.Sub(len(val.sss))
		return val.sss
	}
	return nil
}

//RemoveExpiredValues deletes all expired entries.
func (c *PendingQueryImpl) RemoveExpiredValues() {
	c.qmux.Lock()
	c.tmux.Lock()
	defer c.qmux.Unlock()
	defer c.tmux.Unlock()

	for k, v := range c.tokenMap {
		if v.expiration < time.Now().Unix() {
			delete(c.tokenMap, k)
			key, _ := pqcKey(v.sss[0].Sections) //error case is catched in Add method.
			delete(c.queryMap, key)             //all sss have the same pqcKey
			c.counter.Sub(len(v.sss))
		}
	}
}

//Len returns the number of sections in the cache
func (c *PendingQueryImpl) Len() int {
	return c.counter.Value()
}
