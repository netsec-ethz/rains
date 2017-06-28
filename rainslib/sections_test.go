package rainslib

import (
	"encoding/hex"
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
		{nil, "A_nil"},
		{new(AssertionSection), "A____[]_[]"},
		{&AssertionSection{SubjectName: "name", SubjectZone: "zone", Context: "ctx", Content: GetAllValidObjects()[:3],
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"A_name_zone_ctx_[{1 {ethz2.ch [3 2]}} {2 2001:0db8:85a3:0000:0000:8a2e:0370:7334} {3 127.0.0.1}]_[{KS=0 AT=1 VS=1000 VU=2000 data=53696744617461}]"},
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
		{nil, "S_nil"},
		{new(ShardSection), "S_____[]_[]"},
		{&ShardSection{SubjectZone: "zone", Context: "ctx", RangeFrom: "RB", RangeTo: "RT", Content: []*AssertionSection{new(AssertionSection)},
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"S_zone_ctx_RB_RT_[A____[]_[]]_[{KS=0 AT=1 VS=1000 VU=2000 data=53696744617461}]"},
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
		{nil, "Z_nil"},
		{new(ZoneSection), "Z___[]_[]"},
		{&ZoneSection{SubjectZone: "zone", Context: "ctx", Content: []MessageSectionWithSigForward{new(AssertionSection), new(ShardSection)},
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"Z_zone_ctx_[A____[]_[] S_____[]_[]]_[{KS=0 AT=1 VS=1000 VU=2000 data=53696744617461}]"},
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
		{nil, "AA_nil"},
		{new(AddressAssertionSection), "AA_<nil>__[]_[]"},
		{&AddressAssertionSection{SubjectAddr: subjectAddress1, Context: "ctx", Content: objects2,
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"AA_127.0.0.1/32_ctx_[{1 {ethz2.ch [3 2]}}]_[{KS=0 AT=1 VS=1000 VU=2000 data=53696744617461}]"},
		{&AddressAssertionSection{SubjectAddr: subjectAddress2, Context: "ctx", Content: objects1,
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			fmt.Sprintf("AA_2001:db8::/32_ctx_[{4 ns.ethz.ch} {5 {1 0 %v 10000 50000}} {10 Registrant information}]_[{KS=0 AT=1 VS=1000 VU=2000 data=53696744617461}]",
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
		{nil, "AZ_nil"},
		{new(AddressZoneSection), "AZ_<nil>__[]_[]"},
		{&AddressZoneSection{SubjectAddr: subjectAddress1, Context: "ctx", Content: []*AddressAssertionSection{new(AddressAssertionSection), new(AddressAssertionSection)},
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"AZ_127.0.0.1/32_ctx_[AA_<nil>__[]_[] AA_<nil>__[]_[]]_[{KS=0 AT=1 VS=1000 VU=2000 data=53696744617461}]"},
		{&AddressZoneSection{SubjectAddr: subjectAddress2, Context: "ctx", Content: []*AddressAssertionSection{new(AddressAssertionSection), new(AddressAssertionSection)},
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"AZ_2001:db8::/32_ctx_[AA_<nil>__[]_[] AA_<nil>__[]_[]]_[{KS=0 AT=1 VS=1000 VU=2000 data=53696744617461}]"},
	}
	for i, test := range tests {
		if test.input.Hash() != test.want {
			t.Errorf("%d: Wrong addressZone hash. expected=%v, actual=%v", i, test.want, test.input.Hash())
		}
	}
}

func TestEqualContextZoneName(t *testing.T) {
	var tests = []struct {
		input *AssertionSection
		param *AssertionSection
		want  bool
	}{
		{new(AssertionSection), nil, false},
		{new(AssertionSection), new(AssertionSection), true},
		{&AssertionSection{SubjectName: "name", SubjectZone: "zone", Context: "ctx"}, new(AssertionSection), false},
		{&AssertionSection{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&AssertionSection{SubjectName: "name", SubjectZone: "zone", Context: "ctx"}, true},
		{&AssertionSection{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&AssertionSection{SubjectName: "diffname", SubjectZone: "zone", Context: "ctx"}, false},
		{&AssertionSection{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&AssertionSection{SubjectName: "name", SubjectZone: "diffzone", Context: "ctx"}, false},
		{&AssertionSection{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&AssertionSection{SubjectName: "name", SubjectZone: "zone", Context: "diffctx"}, false},
		{&AssertionSection{SubjectName: "name", SubjectZone: "zone", Context: "ctx"},
			&AssertionSection{SubjectName: "diffname", SubjectZone: "diffzone", Context: "diffctx"}, false},
	}
	for i, test := range tests {
		if test.input.EqualContextZoneName(test.param) != test.want {
			t.Errorf("%d: EqualContextZoneName() returns incorrect result. expected=%v, actual=%v", i, test.want, test.input.EqualContextZoneName(test.param))
		}
	}
}

func TestAssertionString(t *testing.T) {
	var tests = []struct {
		input *AssertionSection
		want  string
	}{
		{nil, "Assertion:nil"},
		{new(AssertionSection), "Assertion:[SN= SZ= CTX= CONTENT=[] SIG=[]]"},
		{&AssertionSection{SubjectName: "name", SubjectZone: "zone", Context: "ctx", Content: GetAllValidObjects()[:3],
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")},
				Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 3000, ValidUntil: 4000, Data: []byte("SigData2")}}},
			"Assertion:[SN=name SZ=zone CTX=ctx CONTENT=[{1 {ethz2.ch [3 2]}} {2 2001:0db8:85a3:0000:0000:8a2e:0370:7334} {3 127.0.0.1}] SIG=[{KS=0 AT=1 VS=1000 VU=2000 data=53696744617461} {KS=0 AT=1 VS=3000 VU=4000 data=5369674461746132}]]"},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong assertion String(). expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestShardString(t *testing.T) {
	var tests = []struct {
		input *ShardSection
		want  string
	}{
		{nil, "Shard:nil"},
		{new(ShardSection), "Shard:[SZ= CTX= RF= RT= CONTENT=[] SIG=[]]"},
		{&ShardSection{SubjectZone: "zone", Context: "ctx", RangeFrom: "RF", RangeTo: "RT", Content: []*AssertionSection{new(AssertionSection)},
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"Shard:[SZ=zone CTX=ctx RF=RF RT=RT CONTENT=[Assertion:[SN= SZ= CTX= CONTENT=[] SIG=[]]] SIG=[{KS=0 AT=1 VS=1000 VU=2000 data=53696744617461}]]"},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong shard String. expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestZoneString(t *testing.T) {
	var tests = []struct {
		input *ZoneSection
		want  string
	}{
		{nil, "Zone:nil"},
		{new(ZoneSection), "Zone:[SZ= CTX= CONTENT=[] SIG=[]]"},
		{&ZoneSection{SubjectZone: "zone", Context: "ctx", Content: []MessageSectionWithSigForward{new(AssertionSection), new(ShardSection)},
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"Zone:[SZ=zone CTX=ctx CONTENT=[Assertion:[SN= SZ= CTX= CONTENT=[] SIG=[]] Shard:[SZ= CTX= RF= RT= CONTENT=[] SIG=[]]] SIG=[{KS=0 AT=1 VS=1000 VU=2000 data=53696744617461}]]"},
		{&ZoneSection{Content: []MessageSectionWithSigForward{new(ZoneSection)}}, "Zone:[SZ= CTX= CONTENT=[Zone:[SZ= CTX= CONTENT=[] SIG=[]]] SIG=[]]"},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong zone String. expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestAddressAssertionString(t *testing.T) {
	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	_, subjectAddress2, _ := net.ParseCIDR("2001:db8::/32")
	objects1 := append(GetAllValidObjects()[3:5], GetAllValidObjects()[9])
	objects2 := []Object{GetAllValidObjects()[0]}
	var tests = []struct {
		input *AddressAssertionSection
		want  string
	}{
		{nil, "AddressAssertion:nil"},
		{new(AddressAssertionSection), "AddressAssertion:[SA=<nil> CTX= CONTENT=[] SIG=[]]"},
		{&AddressAssertionSection{SubjectAddr: subjectAddress1, Context: "ctx", Content: objects2,
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"AddressAssertion:[SA=127.0.0.1/32 CTX=ctx CONTENT=[{1 {ethz2.ch [3 2]}}] SIG=[{KS=0 AT=1 VS=1000 VU=2000 data=53696744617461}]]"},
		{&AddressAssertionSection{SubjectAddr: subjectAddress2, Context: "ctx", Content: objects1,
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			fmt.Sprintf("AddressAssertion:[SA=2001:db8::/32 CTX=ctx CONTENT=[{4 ns.ethz.ch} {5 {1 0 %v 10000 50000}} {10 Registrant information}] SIG=[{KS=0 AT=1 VS=1000 VU=2000 data=53696744617461}]]",
				objects1[1].Value.(PublicKey).Key)},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong addressAssertion String. expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestAddressZoneString(t *testing.T) {
	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	_, subjectAddress2, _ := net.ParseCIDR("2001:db8::/32")
	var tests = []struct {
		input *AddressZoneSection
		want  string
	}{
		{nil, "AddressZone:nil"},
		{new(AddressZoneSection), "AddressZone:[SA=<nil> CTX= CONTENT=[] SIG=[]]"},
		{&AddressZoneSection{SubjectAddr: subjectAddress1, Context: "ctx", Content: []*AddressAssertionSection{new(AddressAssertionSection), new(AddressAssertionSection)},
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"AddressZone:[SA=127.0.0.1/32 CTX=ctx CONTENT=[AddressAssertion:[SA=<nil> CTX= CONTENT=[] SIG=[]] AddressAssertion:[SA=<nil> CTX= CONTENT=[] SIG=[]]] SIG=[{KS=0 AT=1 VS=1000 VU=2000 data=53696744617461}]]"},
		{&AddressZoneSection{SubjectAddr: subjectAddress2, Context: "ctx", Content: []*AddressAssertionSection{new(AddressAssertionSection), new(AddressAssertionSection)},
			Signatures: []Signature{Signature{KeySpace: RainsKeySpace, Algorithm: Ed25519, ValidSince: 1000, ValidUntil: 2000, Data: []byte("SigData")}}},
			"AddressZone:[SA=2001:db8::/32 CTX=ctx CONTENT=[AddressAssertion:[SA=<nil> CTX= CONTENT=[] SIG=[]] AddressAssertion:[SA=<nil> CTX= CONTENT=[] SIG=[]]] SIG=[{KS=0 AT=1 VS=1000 VU=2000 data=53696744617461}]]"},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong addressZone String. expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestQueryString(t *testing.T) {
	token := GenerateToken()
	var tests = []struct {
		input *QuerySection
		want  string
	}{
		{nil, "Query:nil"},
		{new(QuerySection), "Query:[TOK=00000000000000000000000000000000 CTX= NA= TYPE=0 EXP=0 OPT=[]]"},
		{&QuerySection{Token: token, Context: "ctx", Name: "name", Type: OTName, Expires: 100, Options: []QueryOption{QOMinE2ELatency, QOMinInfoLeakage}},
			fmt.Sprintf("Query:[TOK=%s CTX=ctx NA=name TYPE=1 EXP=100 OPT=[1 3]]", hex.EncodeToString(token[:]))},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong query String(). expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestAddressQueryString(t *testing.T) {
	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	_, subjectAddress2, _ := net.ParseCIDR("2001:db8::/32")
	token := GenerateToken()
	var tests = []struct {
		input *AddressQuerySection
		want  string
	}{
		{nil, "AddressQuery:nil"},
		{new(AddressQuerySection), "AddressQuery:[TOK=00000000000000000000000000000000 SA=<nil> CTX= TYPE=0 EXP=0 OPT=[]]"},
		{&AddressQuerySection{Token: token, SubjectAddr: subjectAddress1, Context: "ctx", Type: OTName, Expires: 100,
			Options: []QueryOption{QOMinE2ELatency, QOMinInfoLeakage}},
			fmt.Sprintf("AddressQuery:[TOK=%s SA=127.0.0.1/32 CTX=ctx TYPE=1 EXP=100 OPT=[1 3]]", hex.EncodeToString(token[:]))},
		{&AddressQuerySection{Token: token, SubjectAddr: subjectAddress2, Context: "ctx", Type: OTName, Expires: 100,
			Options: []QueryOption{QOMinE2ELatency, QOMinInfoLeakage}},
			fmt.Sprintf("AddressQuery:[TOK=%s SA=2001:db8::/32 CTX=ctx TYPE=1 EXP=100 OPT=[1 3]]", hex.EncodeToString(token[:]))},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong addressQuery String(). expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestNotificationString(t *testing.T) {
	token := GenerateToken()
	var tests = []struct {
		input *NotificationSection
		want  string
	}{
		{nil, "Notification:nil"},
		{new(NotificationSection), "Notification:[TOK=00000000000000000000000000000000 TYPE=0 DATA=]"},
		{&NotificationSection{Token: token, Type: NTBadMessage, Data: "notificationData"},
			fmt.Sprintf("Notification:[TOK=%s TYPE=400 DATA=notificationData]", hex.EncodeToString(token[:]))},
	}
	for i, test := range tests {
		if test.input.String() != test.want {
			t.Errorf("%d: Wrong notification String(). expected=%v, actual=%v", i, test.want, test.input.String())
		}
	}
}

func TestContainsOptions(t *testing.T) {
	var tests = []struct {
		input []QueryOption
		param QueryOption
		want  bool
	}{
		{[]QueryOption{QOCachedAnswersOnly, QOExpiredAssertionsOk}, QOCachedAnswersOnly, true},
		{[]QueryOption{QOCachedAnswersOnly, QOExpiredAssertionsOk}, QOExpiredAssertionsOk, true},
		{[]QueryOption{}, QOCachedAnswersOnly, false},
		{[]QueryOption{QOExpiredAssertionsOk}, QOCachedAnswersOnly, false},
	}
	for i, test := range tests {
		if containsOption(test.param, test.input) != test.want {
			t.Errorf("%d: containsOptions response incorrect. expected=%v, actual=%v", i, test.want, containsOption(test.param, test.input))
		}
		query := &QuerySection{Options: test.input}
		addressquery := &AddressQuerySection{Options: test.input}
		if query.ContainsOption(test.param) != test.want {
			t.Errorf("%d: query.ContainsOptions response incorrect. expected=%v, actual=%v", i, test.want, containsOption(test.param, test.input))
		}
		if addressquery.ContainsOption(test.param) != test.want {
			t.Errorf("%d: addressQuery.ContainsOptions response incorrect. expected=%v, actual=%v", i, test.want, containsOption(test.param, test.input))
		}
	}
}
