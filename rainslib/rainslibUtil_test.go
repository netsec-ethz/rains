package rainslib

import (
	"net"
	"reflect"
	"testing"
	"time"
)

func TestSaveAndLoad(t *testing.T) {
	var tests = []struct {
		input       *AssertionSection
		output      *AssertionSection
		path        string
		storeErrMsg string
		loadErrMsg  string
	}{
		{&AssertionSection{SubjectName: testSubjectName, SubjectZone: testZone, Context: globalContext, Content: []Object{Object{Type: OTIP4Addr, Value: ip4TestAddr}}},
			new(AssertionSection), "test/test.gob", "", ""},
		{&AssertionSection{SubjectName: testSubjectName, SubjectZone: testZone, Context: globalContext, Content: []Object{Object{Type: OTIP4Addr, Value: ip4TestAddr}}},
			nil, "test/test.gob", "", "gob: DecodeValue of unassignable value"},
		{&AssertionSection{SubjectName: testSubjectName, SubjectZone: "ch", Context: globalContext, Content: []Object{Object{Type: OTIP4Addr, Value: ip4TestAddr}}},
			new(AssertionSection), "nonExistDir/test.gob", "open nonExistDir/test.gob: no such file or directory", "open nonExistDir/test.gob: no such file or directory"},
	}
	for i, test := range tests {
		err := Save(test.path, test.input)
		if err != nil && err.Error() != test.storeErrMsg {
			t.Errorf("%d: Was not able to save data and error msgs do notmatch. expected=%s actual=%s", i, test.storeErrMsg, err.Error())
		}
		err = Load(test.path, test.output)
		if err != nil && err.Error() != test.loadErrMsg {
			t.Errorf("%d: Was not able to load data and error msgs do notmatch. expected=%s actual=%s", i, test.loadErrMsg, err.Error())
		}
		if err == nil && !reflect.DeepEqual(test.output, test.input) {
			t.Errorf("%d: Loaded object has different value. expected=%v actual=%v", i, test.input, test.output)
		}
	}
}

func TestGenerateToken(t *testing.T) {
	t1 := GenerateToken()
	t2 := GenerateToken()
	if t1 == t2 {
		t.Errorf("Subsequent generated tokens should not have the same value t1=%s t2=%s", t1, t2)
	}
}

func TestUpdateSectionValidity(t *testing.T) {
	now := time.Now().Unix()
	var tests = []struct {
		input          MessageSectionWithSig
		pkeyValidSince int64
		pkeyValidUntil int64
		sigValidSince  int64
		sigValidUntil  int64
		maxVal         MaxCacheValidity
		wantValidSince int64
		wantValidUntil int64
	}{
		{input: nil}, //should not result in panic
		{new(AssertionSection), now + 1, now + 4, now + 2, now + 3, MaxCacheValidity{AssertionValidity: 4 * time.Second}, now + 2, now + 3},
		{new(AssertionSection), now + 2, now + 3, now + 1, now + 4, MaxCacheValidity{AssertionValidity: 4 * time.Second}, now + 2, now + 3},
		{new(AssertionSection), now + 1, now + 3, now + 2, now + 4, MaxCacheValidity{AssertionValidity: 4 * time.Second}, now + 2, now + 3},
		{new(AssertionSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{AssertionValidity: 4 * time.Second}, now + 2, now + 3},
		{new(AssertionSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{AssertionValidity: 2 * time.Second}, now + 2, now + 2},
		{new(AssertionSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{AssertionValidity: 1 * time.Second}, now + 1, now + 1},

		{new(ShardSection), now + 1, now + 4, now + 2, now + 3, MaxCacheValidity{ShardValidity: 4 * time.Second}, now + 2, now + 3},
		{new(ShardSection), now + 2, now + 3, now + 1, now + 4, MaxCacheValidity{ShardValidity: 4 * time.Second}, now + 2, now + 3},
		{new(ShardSection), now + 1, now + 3, now + 2, now + 4, MaxCacheValidity{ShardValidity: 4 * time.Second}, now + 2, now + 3},
		{new(ShardSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{ShardValidity: 4 * time.Second}, now + 2, now + 3},
		{new(ShardSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{ShardValidity: 2 * time.Second}, now + 2, now + 2},
		{new(ShardSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{ShardValidity: 1 * time.Second}, now + 1, now + 1},

		{new(ZoneSection), now + 1, now + 4, now + 2, now + 3, MaxCacheValidity{ZoneValidity: 4 * time.Second}, now + 2, now + 3},
		{new(ZoneSection), now + 2, now + 3, now + 1, now + 4, MaxCacheValidity{ZoneValidity: 4 * time.Second}, now + 2, now + 3},
		{new(ZoneSection), now + 1, now + 3, now + 2, now + 4, MaxCacheValidity{ZoneValidity: 4 * time.Second}, now + 2, now + 3},
		{new(ZoneSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{ZoneValidity: 4 * time.Second}, now + 2, now + 3},
		{new(ZoneSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{ZoneValidity: 2 * time.Second}, now + 2, now + 2},
		{new(ZoneSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{ZoneValidity: 1 * time.Second}, now + 1, now + 1},

		{new(AddressAssertionSection), now + 1, now + 4, now + 2, now + 3, MaxCacheValidity{AddressAssertionValidity: 4 * time.Second}, now + 2, now + 3},
		{new(AddressAssertionSection), now + 2, now + 3, now + 1, now + 4, MaxCacheValidity{AddressAssertionValidity: 4 * time.Second}, now + 2, now + 3},
		{new(AddressAssertionSection), now + 1, now + 3, now + 2, now + 4, MaxCacheValidity{AddressAssertionValidity: 4 * time.Second}, now + 2, now + 3},
		{new(AddressAssertionSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{AddressAssertionValidity: 4 * time.Second}, now + 2, now + 3},
		{new(AddressAssertionSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{AddressAssertionValidity: 2 * time.Second}, now + 2, now + 2},
		{new(AddressAssertionSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{AddressAssertionValidity: 1 * time.Second}, now + 1, now + 1},

		{new(AddressZoneSection), now + 1, now + 4, now + 2, now + 3, MaxCacheValidity{AddressZoneValidity: 4 * time.Second}, now + 2, now + 3},
		{new(AddressZoneSection), now + 2, now + 3, now + 1, now + 4, MaxCacheValidity{AddressZoneValidity: 4 * time.Second}, now + 2, now + 3},
		{new(AddressZoneSection), now + 1, now + 3, now + 2, now + 4, MaxCacheValidity{AddressZoneValidity: 4 * time.Second}, now + 2, now + 3},
		{new(AddressZoneSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{AddressZoneValidity: 4 * time.Second}, now + 2, now + 3},
		{new(AddressZoneSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{AddressZoneValidity: 2 * time.Second}, now + 2, now + 2},
		{new(AddressZoneSection), now + 2, now + 4, now + 1, now + 3, MaxCacheValidity{AddressZoneValidity: 1 * time.Second}, now + 1, now + 1},
	}
	for i, test := range tests {
		UpdateSectionValidity(test.input, test.pkeyValidSince, test.pkeyValidUntil, test.sigValidSince, test.sigValidUntil, test.maxVal)
		if test.input != nil && test.input.ValidSince() != test.wantValidSince {
			t.Errorf("%d: ValidSince does not match. expected=%d actual=%d", i, test.wantValidSince, test.input.ValidSince())
		}
		if test.input != nil && test.input.ValidUntil() != test.wantValidUntil {
			t.Errorf("%d: ValidUntil does not match. expected=%d actual=%d", i, test.wantValidUntil, test.input.ValidUntil())
		}
	}
}

func TestNewQueryMessage(t *testing.T) {
	token := GenerateToken()
	var tests = []struct {
		context  string
		name     string
		expires  int64
		types    []ObjectType
		options  []QueryOption
		token    Token
		expected RainsMessage
	}{
		{".", "example.com", 100, []ObjectType{OTIP4Addr}, []QueryOption{QOTokenTracing, QOMinE2ELatency}, token,
			RainsMessage{
				Token: token,
				Content: []MessageSection{
					&QuerySection{
						Name:    "example.com",
						Context: ".",
						Expires: 100,
						Types:   []ObjectType{OTIP4Addr},
						Options: []QueryOption{QOTokenTracing, QOMinE2ELatency},
					},
				},
			},
		},
	}
	for i, test := range tests {
		msg := NewQueryMessage(test.name, test.context, test.expires, test.types, test.options, test.token)
		if !reflect.DeepEqual(test.expected, msg) {
			t.Errorf("%d: Message containing Query do not match. expected=%v actual=%v", i, test.expected, msg)
		}
	}
}

func TestNewAddressQueryMessage(t *testing.T) {
	token := GenerateToken()
	_, subjectAddress1, _ := net.ParseCIDR(ip4TestAddrCIDR32)
	_, subjectAddress2, _ := net.ParseCIDR(ip6TestAddrCIDR)
	var tests = []struct {
		context  string
		ipNet    *net.IPNet
		expires  int64
		types    []ObjectType
		options  []QueryOption
		token    Token
		expected RainsMessage
	}{
		{".", subjectAddress1, 100, []ObjectType{OTIP4Addr}, []QueryOption{QOTokenTracing, QOMinE2ELatency}, token,
			RainsMessage{
				Token: token,
				Content: []MessageSection{
					&AddressQuerySection{
						SubjectAddr: subjectAddress1,
						Context:     ".",
						Expires:     100,
						Types:       []ObjectType{OTIP4Addr},
						Options:     []QueryOption{QOTokenTracing, QOMinE2ELatency},
					},
				},
			},
		},
		{".", subjectAddress2, 100, []ObjectType{OTIP4Addr}, []QueryOption{QOTokenTracing, QOMinE2ELatency}, token,
			RainsMessage{
				Token: token,
				Content: []MessageSection{
					&AddressQuerySection{
						SubjectAddr: subjectAddress2,
						Context:     ".",
						Expires:     100,
						Types:       []ObjectType{OTIP4Addr},
						Options:     []QueryOption{QOTokenTracing, QOMinE2ELatency},
					},
				},
			},
		},
	}
	for i, test := range tests {
		msg := NewAddressQueryMessage(test.context, test.ipNet, test.expires, test.types, test.options, test.token)
		if !reflect.DeepEqual(test.expected, msg) {
			t.Errorf("%d: Message containing Query do not match. expected=%v actual=%v", i, test.expected, msg)
		}
	}
}

func TestNewNotificationsMessage(t *testing.T) {
	tokens := []Token{}
	for i := 0; i < 10; i++ {
		tokens = append(tokens, GenerateToken())
	}
	var tests = []struct {
		tokens   []Token
		types    []NotificationType
		data     []string
		expected RainsMessage
		errMsg   string
	}{
		{tokens[:2], []NotificationType{NTHeartbeat, NTMsgTooLarge}, []string{"1", "2"},
			RainsMessage{Content: []MessageSection{&NotificationSection{Token: tokens[0], Type: NTHeartbeat, Data: "1"},
				&NotificationSection{Token: tokens[1], Type: NTMsgTooLarge, Data: "2"}}}, ""},
		{tokens[:3], []NotificationType{NTHeartbeat, NTMsgTooLarge}, []string{"1", "2"}, RainsMessage{}, "input slices have not the same length"},
	}
	for i, test := range tests {
		msg, err := NewNotificationsMessage(test.tokens, test.types, test.data)
		test.expected.Token = msg.Token
		if err == nil && !reflect.DeepEqual(test.expected, msg) {
			t.Errorf("%d: Message containing Notifications do not match. expected=%v actual=%v", i, test.expected, msg)
		}
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: error msg do not match. expected=%v actual=%v", i, test.errMsg, err.Error())
		}
	}
}

func TestNewNotificationMessage(t *testing.T) {
	token := GenerateToken()
	var tests = []struct {
		token    Token
		t        NotificationType
		data     string
		expected RainsMessage
	}{
		{token, NTHeartbeat, "1",
			RainsMessage{Content: []MessageSection{&NotificationSection{Token: token, Type: NTHeartbeat, Data: "1"}}}},
	}
	for i, test := range tests {
		msg := NewNotificationMessage(test.token, test.t, test.data)
		test.expected.Token = msg.Token
		if !reflect.DeepEqual(test.expected, msg) {
			t.Errorf("%d: Message containing Notification do not match. expected=%v actual=%v", i, test.expected, msg)
		}
	}
}
