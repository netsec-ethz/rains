package safeCounter

import (
	"fmt"
	"sync"

	log "github.com/inconshreveable/log15"
)

//Counter is a concurrency safe counter
type Counter struct {
	maxCount int
	count    int
	mux      sync.Mutex
}

//New returns a new concurrency safe hash map
func New(maxcount int) *Counter {
	return &Counter{maxCount: maxcount, count: 0}
}

//Inc increases the count by one. it returns false if count < maxCount
func (m *Counter) Inc() bool {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.count++
	return m.count >= m.maxCount
}

//Add increases the count by i. it returns false if count < maxCount
func (m *Counter) Add(i int) bool {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.count += i
	return m.count >= m.maxCount
}

//Dec decrements the count by one.
func (m *Counter) Dec() {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.count--
	if m.count < 0 {
		log.Error("counter should never be negative", "counter", m.count)
	}
}

//Sub decreases the count by i.
func (m *Counter) Sub(i int) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.count -= i
	if m.count < 0 {
		log.Error("counter should never be negative", "counter", m.count)
	}
}

//Value returns the current value of the counter
func (m *Counter) Value() int {
	m.mux.Lock()
	defer m.mux.Unlock()
	return m.count
}

//Info returns the current value of the counter and the maxCount
func (m *Counter) Info() (int, int) {
	m.mux.Lock()
	defer m.mux.Unlock()
	return m.count, m.maxCount
}

//IsFull returns true if count is larger or equal to maxCount.
func (m *Counter) IsFull() bool {
	return m.count >= m.maxCount
}

func (m *Counter) String() string {
	return fmt.Sprintf("%d/%d", m.count, m.maxCount)
}
