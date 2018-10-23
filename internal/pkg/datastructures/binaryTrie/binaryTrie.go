package binaryTrie

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/datastructures/set"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"

	log "github.com/inconshreveable/log15"
)

//TrieNode is a node of a binary trie.
type TrieNode struct {
	child      [2]*TrieNode
	assertions map[object.Type]*set.Set
	zones      *set.Set
	mutex      sync.RWMutex
}

//Get returns the most specific address assertion or zone in relation to the given netAddress' prefix.
//If no address assertion or zone is found it return false
func (t *TrieNode) Get(netAddr *net.IPNet, types []object.Type) (*section.AddrAssertion, bool) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return get(t, netAddr, types, 0)
}

func get(t *TrieNode, netAddr *net.IPNet, types []object.Type, depth int) (*section.AddrAssertion, bool) {
	addrmasks := [8]byte{0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01}
	prfLength, _ := netAddr.Mask.Size()
	if depth < prfLength {
		var childidx int
		if netAddr.IP[depth/8]&addrmasks[depth%8] == 0 {
			childidx = 0
		} else {
			childidx = 1
		}

		if t.child[childidx] == nil {
			return containedElement(t, types)
		}

		if a, ok := get(t.child[childidx], netAddr, types, depth+1); ok {
			return a, ok
		}
	}
	return containedElement(t, types)
}

//containedElement returns true and the first addressAssertion that matches one of the given connection or if none is found the first addressZone (if present).
//in case there is neither false is returned
func containedElement(t *TrieNode, types []object.Type) (*section.AddrAssertion, bool) {
	for _, obj := range types {
		aSet := t.assertions[obj]
		if aSet != nil && aSet.Len() > 0 {
			return aSet.GetAll()[0].(*section.AddrAssertion), true
		}
	}
	return nil, false
}

//AddAddressAssertion adds the given address assertion to the map (keyed by objectType) at the trie node corresponding to the network address.
//Returns an error if it was not able to add the AddressAssertion
func (t *TrieNode) AddAddressAssertion(assertion *section.AddrAssertion) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	node := getNode(t, assertion.SubjectAddr, 0)
	for _, obj := range assertion.Content {
		if obj.Type != object.OTName && obj.Type != object.OTDelegation && obj.Type != object.OTRedirection && obj.Type != object.OTRegistrant {
			log.Warn("Unsupported type.", "type", obj.Type)
			return errors.New("unsupported object type")
		}
		node.assertions[obj.Type].Add(assertion)
	}
	return nil
}

func getNode(t *TrieNode, ipNet *net.IPNet, depth int) *TrieNode {
	addrmasks := [8]byte{0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01}
	prfLength, _ := ipNet.Mask.Size()

	var subidx int
	if depth < prfLength {
		if ipNet.IP[depth/8]&addrmasks[depth%8] == 0 {
			subidx = 0
		} else {
			subidx = 1
		}

		if t.child[subidx] == nil {
			t.child[subidx] = &TrieNode{assertions: make(map[object.Type]*set.Set)}
			t.child[subidx].zones = set.New()
			t.child[subidx].assertions[object.OTName] = set.New()
			t.child[subidx].assertions[object.OTRedirection] = set.New()
			t.child[subidx].assertions[object.OTRegistrant] = set.New()
			t.child[subidx].assertions[object.OTDelegation] = set.New()

		}
		return getNode(t.child[subidx], ipNet, depth+1)
	}
	return t
}

//DeleteExpiredElements removes all expired elements from the trie. The trie structure is not updated when a node gets empty
func (t *TrieNode) DeleteExpiredElements() {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	for _, s := range t.assertions {
		assertions := s.GetAll()
		for _, a := range assertions {
			if a.(*section.AddrAssertion).ValidUntil() < time.Now().Unix() {
				s.Delete(a)
			}
		}
	}
}
