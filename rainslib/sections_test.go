package rainslib

import (
	"fmt"
	"net"
	"testing"
)

func TestAssertionCopy(t *testing.T) {
	assertion := GetMessage().Content[0].(*AssertionSection)
	aCopy := assertion.Copy(assertion.Context, assertion.SubjectZone)
	CheckAssertion(assertion, aCopy, t)
	if assertion == aCopy {
		t.Error("Assertion was not copied. Pointer is still the same.")
	}
}

func TestShardCopy(t *testing.T) {
	shard := GetMessage().Content[1].(*ShardSection)
	sCopy := shard.Copy(shard.Context, shard.SubjectZone)
	CheckShard(shard, sCopy, t)
	if shard == sCopy {
		t.Error("Assertion was not copied. Pointer is still the same.")
	}
}

func TestAssertionInterval(t *testing.T) {
	var tests = []struct {
		input *AssertionSection
		want  string
	}{
		{&AssertionSection{SubjectName: "test"}, "test"},
		{new(AssertionSection), ""},
	}
	for i, test := range tests {
		if test.input.Begin() != test.want || test.input.End() != test.want {
			t.Errorf("%d: Assertion Begin and End are not as expected=%s actualBegin=%s actualEnd=%s", i, test.want, test.input.Begin(), test.input.End())
		}
	}
}

func TestShardInterval(t *testing.T) {
	var tests = []struct {
		input     *ShardSection
		wantBegin string
		wantEnd   string
	}{
		{&ShardSection{RangeFrom: "a", RangeTo: "z"}, "a", "z"},
		{new(ShardSection), "", ""},
	}
	for i, test := range tests {
		if test.input.Begin() != test.wantBegin || test.input.End() != test.wantEnd {
			t.Errorf("%d: Assertion Begin and End are not as expectedBegin=%s expectedEnd=%s actualBegin=%s actualEnd=%s", i,
				test.wantBegin, test.wantEnd, test.input.Begin(), test.input.End())
		}
	}
}

func TestZoneInterval(t *testing.T) {
	var tests = []struct {
		input *ZoneSection
		want  string
	}{
		{new(ZoneSection), ""},
	}
	for i, test := range tests {
		if test.input.Begin() != test.want || test.input.End() != test.want {
			t.Errorf("%d: Assertion Begin and End are not as expected=%s actualBegin=%s actualEnd=%s", i, test.want, test.input.Begin(), test.input.End())
		}
	}
}

func TestAssertionHash(t *testing.T) {
	var tests = []struct {
		input *AssertionSection
		want  string
	}{
		{new(AssertionSection), "___[]_[]"},
		{&AssertionSection{SubjectName: "name", SubjectZone: "zone", Context: "ctx", Content: GetAllValidObjects()[:3],
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"name_zone_ctx_[{1 {ethz2.ch [3 2]}} {2 2001:0db8:85a3:0000:0000:8a2e:0370:7334} {3 127.0.0.1}]_[KS=0 AT=1 VS=1000 VU=2000 data=53696744617461]"},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong assertion hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}

func TestShardHash(t *testing.T) {
	var tests = []struct {
		input *ShardSection
		want  string
	}{
		{new(ShardSection), "____[]_[]"},
		{&ShardSection{SubjectZone: "zone", Context: "ctx", RangeFrom: "RB", RangeTo: "RT", Content: []*AssertionSection{new(AssertionSection)},
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"zone_ctx_RB_RT_[___[]_[]]_[KS=0 AT=1 VS=1000 VU=2000 data=53696744617461]"},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong shard hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}

func TestZoneHash(t *testing.T) {
	var tests = []struct {
		input *ZoneSection
		want  string
	}{
		{new(ZoneSection), "__[]_[]"},
		{&ZoneSection{SubjectZone: "zone", Context: "ctx", Content: []MessageSectionWithSigForward{new(AssertionSection), new(ShardSection)},
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"zone_ctx_[___[]_[] ____[]_[]]_[KS=0 AT=1 VS=1000 VU=2000 data=53696744617461]"},
		{&ZoneSection{Content: []MessageSectionWithSigForward{new(ZoneSection)}}, ""},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong zone hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}

func TestAddressAssertionHash(t *testing.T) {
	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	_, subjectAddress2, _ := net.ParseCIDR("2001:db8::/32")
	objects1 := append(GetAllValidObjects()[3:5], GetAllValidObjects()[9])
	objects2 := []Object{GetAllValidObjects()[0]}
	var tests = []struct {
		input *AddressAssertionSection
		want  string
	}{
		{new(AddressAssertionSection), "<nil>__[]_[]"},
		{&AddressAssertionSection{SubjectAddr: subjectAddress1, Context: "ctx", Content: objects2,
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"127.0.0.1/32_ctx_[{1 {ethz2.ch [3 2]}}]_[KS=0 AT=1 VS=1000 VU=2000 data=53696744617461]"},
		{&AddressAssertionSection{SubjectAddr: subjectAddress2, Context: "ctx", Content: objects1,
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			fmt.Sprintf("2001:db8::/32_ctx_[{4 ns.ethz.ch} {5 {1 0 %v 10000 50000}} {10 Registrant information}]_[KS=0 AT=1 VS=1000 VU=2000 data=53696744617461]",
				objects1[1].Value.(PublicKey).Key)},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong addressAssertion hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}

func TestAddressZoneHash(t *testing.T) {
	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	_, subjectAddress2, _ := net.ParseCIDR("2001:db8::/32")
	var tests = []struct {
		input *AddressZoneSection
		want  string
	}{
		{new(AddressZoneSection), "<nil>__[]_[]"},
		{&AddressZoneSection{SubjectAddr: subjectAddress1, Context: "ctx", Content: []*AddressAssertionSection{new(AddressAssertionSection), new(AddressAssertionSection)},
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"127.0.0.1/32_ctx_[<nil>__[]_[] <nil>__[]_[]]_[KS=0 AT=1 VS=1000 VU=2000 data=53696744617461]"},
		{&AddressZoneSection{SubjectAddr: subjectAddress2, Context: "ctx", Content: []*AddressAssertionSection{new(AddressAssertionSection), new(AddressAssertionSection)},
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"2001:db8::/32_ctx_[<nil>__[]_[] <nil>__[]_[]]_[KS=0 AT=1 VS=1000 VU=2000 data=53696744617461]"},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong addressZone hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}
