package binaryTrie

import (
	"net"
	"rains/rainslib"
	"rains/utils/set"
	"testing"

	log "github.com/inconshreveable/log15"
)

func TestAddAndFind(t *testing.T) {

	publicKey := rainslib.PublicKey{
		Type:       rainslib.Ed25519,
		Key:        []byte("TestKey"),
		ValidSince: 10000,
		ValidUntil: 50000,
	}

	nameObject := rainslib.Object{Type: rainslib.OTName, Value: "ethz2.ch"}
	//ip6Object := rainslib.Object{Type: rainslib.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
	//ip4Object := rainslib.Object{Type: rainslib.OTIP4Addr, Value: "127.0.0.1"}
	redirObject := rainslib.Object{Type: rainslib.OTRedirection, Value: "ns.ethz.ch"}
	delegObject := rainslib.Object{Type: rainslib.OTDelegation, Value: publicKey}
	registrantObject := rainslib.Object{Type: rainslib.OTRegistrant, Value: "Registrant information"}

	signature := rainslib.Signature{
		KeySpace:   rainslib.RainsKeySpace,
		Algorithm:  rainslib.Ed25519,
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

	addressAssertion1 := &rainslib.AddressAssertionSection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Content:     []rainslib.Object{nameObject},
		Signatures:  []rainslib.Signature{signature},
	}

	addressAssertion2 := &rainslib.AddressAssertionSection{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     []rainslib.Object{redirObject, delegObject, registrantObject},
		Signatures:  []rainslib.Signature{signature},
	}

	addressZone1 := &rainslib.AddressZoneSection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Content:     []*rainslib.AddressAssertionSection{addressAssertion1, addressAssertion2},
		Signatures:  []rainslib.Signature{signature},
	}

	addressZone2 := &rainslib.AddressZoneSection{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     []*rainslib.AddressAssertionSection{addressAssertion1, addressAssertion2},
		Signatures:  []rainslib.Signature{signature},
	}

	addressAssertion3 := &rainslib.AddressAssertionSection{
		SubjectAddr: subjectAddress5,
		Context:     ".",
		Content:     []rainslib.Object{nameObject},
		Signatures:  []rainslib.Signature{signature},
	}

	addressAssertion4 := &rainslib.AddressAssertionSection{
		SubjectAddr: subjectAddress6,
		Context:     ".",
		Content:     []rainslib.Object{redirObject, delegObject, registrantObject},
		Signatures:  []rainslib.Signature{signature},
	}

	addressZone3 := &rainslib.AddressZoneSection{
		SubjectAddr: subjectAddress5,
		Context:     ".",
		Content:     []*rainslib.AddressAssertionSection{addressAssertion3, addressAssertion4},
		Signatures:  []rainslib.Signature{signature},
	}

	addressZone4 := &rainslib.AddressZoneSection{
		SubjectAddr: subjectAddress6,
		Context:     ".",
		Content:     []*rainslib.AddressAssertionSection{addressAssertion3, addressAssertion4},
		Signatures:  []rainslib.Signature{signature},
	}

	/*
	* IPv4
	 */

	trie := &TrieNode{assertions: make(map[rainslib.ObjectType]*set.Set)}
	trie.zones = set.New()
	trie.assertions[rainslib.OTName] = set.New()
	trie.assertions[rainslib.OTRedirection] = set.New()
	trie.assertions[rainslib.OTRegistrant] = set.New()
	trie.assertions[rainslib.OTDelegation] = set.New()

	trie.AddAddressAssertion(addressAssertion1)
	a, z, ok := trie.Get(subjectAddress1, []rainslib.ObjectType{rainslib.OTName})
	if a != addressAssertion1 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Added AddressAssertion not returned by the cache")
	}
	trie.AddAddressZone(addressZone2)
	a, z, ok = trie.Get(subjectAddress2, []rainslib.ObjectType{})
	if z != addressZone2 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Added AddressZone not returned by the cache")
	}
	a, z, ok = trie.Get(subjectAddress3, []rainslib.ObjectType{})
	if z != addressZone2 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Less specific AddressZone not returned by the trie")
	}
	a, z, ok = trie.Get(subjectAddress4, []rainslib.ObjectType{})
	if ok {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("No entry should be returned. There is no less specific one")
	}

	trie.AddAddressZone(addressZone1)
	a, z, ok = trie.Get(subjectAddress1, []rainslib.ObjectType{rainslib.OTName})
	if a != addressAssertion1 || z != nil {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Assertions have priority over zone")
	}

	a, z, ok = trie.Get(subjectAddress1, []rainslib.ObjectType{rainslib.OTDelegation})
	if a != nil || z != addressZone1 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Assertion should not be returned. The type does not match.")
	}

	/*
	* IPv6
	 */

	trie = &TrieNode{assertions: make(map[rainslib.ObjectType]*set.Set)}
	trie.zones = set.New()
	trie.assertions[rainslib.OTName] = set.New()
	trie.assertions[rainslib.OTRedirection] = set.New()
	trie.assertions[rainslib.OTRegistrant] = set.New()
	trie.assertions[rainslib.OTDelegation] = set.New()

	trie.AddAddressAssertion(addressAssertion3)
	a, z, ok = trie.Get(subjectAddress5, []rainslib.ObjectType{rainslib.OTName})
	if a != addressAssertion3 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Added AddressAssertion not returned by the cache")
	}
	trie.AddAddressZone(addressZone4)
	a, z, ok = trie.Get(subjectAddress6, []rainslib.ObjectType{})
	if z != addressZone4 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Added AddressZone not returned by the cache")
	}
	a, z, ok = trie.Get(subjectAddress7, []rainslib.ObjectType{})
	if z != addressZone4 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Less specific AddressZone not returned by the trie")
	}
	a, z, ok = trie.Get(subjectAddress8, []rainslib.ObjectType{})
	if ok {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("No entry should be returned. There is no less specific one")
	}

	trie.AddAddressZone(addressZone3)
	a, z, ok = trie.Get(subjectAddress5, []rainslib.ObjectType{rainslib.OTName})
	if a != addressAssertion3 || z != nil {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Assertions have priority over zone")
	}

	a, z, ok = trie.Get(subjectAddress5, []rainslib.ObjectType{rainslib.OTDelegation})
	if a != nil || z != addressZone3 {
		log.Warn("", "assertion", a, "zone", z, "ok", ok)
		t.Error("Assertion should not be returned. The type does not match.")
	}
}
