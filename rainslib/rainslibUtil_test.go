package rainslib

import (
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
		{&AssertionSection{SubjectName: "ethz", SubjectZone: "ch", Context: ".", Content: []Object{Object{Type: OTIP4Addr, Value: "127.0.0.1"}}},
			new(AssertionSection), "test/test.gob", "", ""},
		{&AssertionSection{SubjectName: "ethz", SubjectZone: "ch", Context: ".", Content: []Object{Object{Type: OTIP4Addr, Value: "127.0.0.1"}}},
			nil, "test/test.gob", "", "gob: DecodeValue of unassignable value"},
		{&AssertionSection{SubjectName: "ethz", SubjectZone: "ch", Context: ".", Content: []Object{Object{Type: OTIP4Addr, Value: "127.0.0.1"}}},
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
