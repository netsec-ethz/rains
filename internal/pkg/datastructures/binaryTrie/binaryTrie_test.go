package binaryTrie

import (
	"net"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/datastructures/set"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/signature"

	log "github.com/inconshreveable/log15"
)

func TestAddAndFind(t *testing.T) {

	publicKey := keys.PublicKey{
		PublicKeyID: keys.PublicKeyID{
			Algorithm: keys.Ed25519,
		},
		Key:        []byte("TestKey"),
		ValidSince: 10000,
		ValidUntil: 50000,
	}

	nameObject := object.Object{Type: object.OTName, Value: "ethz2.ch"}
	redirObject := object.Object{Type: object.OTRedirection, Value: "ns.ethz.ch"}
	delegObject := object.Object{Type: object.OTDelegation, Value: publicKey}
	registrantObject := object.Object{Type: object.OTRegistrant, Value: "Registrant information"}

	signature := signature.Sig{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			Algorithm: keys.Ed25519,
		},
		ValidSince: 1000,
		ValidUntil: 1000000000,
		Data:       []byte("SignatureData")}

	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	_, subjectAddress2, _ := net.ParseCIDR("10.0.0.0/8")
	_, subjectAddress3, _ := net.ParseCIDR("10.0.0.0/9")
	_, subjectAddress4, _ := net.ParseCIDR("10.0.0.0/6")

	_, subjectAddress5, _ := net.ParseCIDR("127B::/128")
	_, subjectAddress6, _ := net.ParseCIDR("10AA::/8")
	_, subjectAddress7, _ := net.ParseCIDR("10AA::/9")
	_, subjectAddress8, _ := net.ParseCIDR("10AA::/6")

	addressAssertion1 := &section.AddrAssertion{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Content:     []object.Object{nameObject},
		Signatures:  []signature.Signature{signature},
	}

	addressAssertion2 := &section.AddrAssertion{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     []object.Object{redirObject, delegObject, registrantObject},
		Signatures:  []signature.Signature{signature},
	}

	addressZone1 := &section.AddressZoneSection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Content:     []*section.AddrAssertion{addressAssertion1, addressAssertion2},
		Signatures:  []signature.Signature{signature},
	}

	addressZone2 := &section.AddressZoneSection{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     []*section.AddrAssertion{addressAssertion1, addressAssertion2},
		Signatures:  []signature.Signature{signature},
	}

	addressAssertion3 := &section.AddrAssertion{
		SubjectAddr: subjectAddress5,
		Context:     ".",
		Content:     []object.Object{nameObject},
		Signatures:  []signature.Signature{signature},
	}

	addressAssertion4 := &section.AddrAssertion{
		SubjectAddr: subjectAddress6,
		Context:     ".",
		Content:     []object.Object{redirObject, delegObject, registrantObject},
		Signatures:  []signature.Signature{signature},
	}

	addressZone3 := &section.AddressZoneSection{
		SubjectAddr: subjectAddress5,
		Context:     ".",
		Content:     []*section.AddrAssertion{addressAssertion3, addressAssertion4},
		Signatures:  []signature.Signature{signature},
	}

	addressZone4 := &section.AddressZoneSection{
		SubjectAddr: subjectAddress6,
		Context:     ".",
		Content:     []*section.AddrAssertion{addressAssertion3, addressAssertion4},
		Signatures:  []signature.Signature{signature},
	}

	/*
	* IPv4
	 */

	trie := &TrieNode{assertions: make(map[object.Type]*set.Set)}
	trie.zones = set.New()
	trie.assertions[object.OTName] = set.New()
	trie.assertions[object.OTRedirection] = set.New()
	trie.assertions[object.OTRegistrant] = set.New()
	trie.assertions[object.OTDelegation] = set.New()

	trie.AddAddressAssertion(addressAssertion1)
	a, z, ok := trie.Get(subjectAddress1, []object.Type{object.OTName})
	if a != addressAssertion1 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Added AddressAssertion not returned by the cache")
	}
	trie.AddAddressZone(addressZone2)
	a, z, ok = trie.Get(subjectAddress2, []object.Type{})
	if z != addressZone2 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Added AddressZone not returned by the cache")
	}
	a, z, ok = trie.Get(subjectAddress3, []object.Type{})
	if z != addressZone2 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Less specific AddressZone not returned by the trie")
	}
	a, z, ok = trie.Get(subjectAddress4, []object.Type{})
	if ok {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("No entry should be returned. There is no less specific one")
	}

	trie.AddAddressZone(addressZone1)
	a, z, ok = trie.Get(subjectAddress1, []object.Type{object.OTName})
	if a != addressAssertion1 || z != nil {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Assertions have priority over zone")
	}

	a, z, ok = trie.Get(subjectAddress1, []object.Type{object.OTDelegation})
	if a != nil || z != addressZone1 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Assertion should not be returned. The type does not match.")
	}

	/*
	* IPv6
	 */

	trie = &TrieNode{assertions: make(map[object.Type]*set.Set)}
	trie.zones = set.New()
	trie.assertions[object.OTName] = set.New()
	trie.assertions[object.OTRedirection] = set.New()
	trie.assertions[object.OTRegistrant] = set.New()
	trie.assertions[object.OTDelegation] = set.New()

	trie.AddAddressAssertion(addressAssertion3)
	a, z, ok = trie.Get(subjectAddress5, []object.Type{object.OTName})
	if a != addressAssertion3 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Added AddressAssertion not returned by the cache")
	}
	trie.AddAddressZone(addressZone4)
	a, z, ok = trie.Get(subjectAddress6, []object.Type{})
	if z != addressZone4 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Added AddressZone not returned by the cache")
	}
	a, z, ok = trie.Get(subjectAddress7, []object.Type{})
	if z != addressZone4 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Less specific AddressZone not returned by the trie")
	}
	a, z, ok = trie.Get(subjectAddress8, []object.Type{})
	if ok {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("No entry should be returned. There is no less specific one")
	}

	trie.AddAddressZone(addressZone3)
	a, z, ok = trie.Get(subjectAddress5, []object.Type{object.OTName})
	if a != addressAssertion3 || z != nil {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Assertions have priority over zone")
	}

	a, z, ok = trie.Get(subjectAddress5, []object.Type{object.OTDelegation})
	if a != nil || z != addressZone3 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Assertion should not be returned. The type does not match.")
	}
}
