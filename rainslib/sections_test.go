package rainslib

import "testing"

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
