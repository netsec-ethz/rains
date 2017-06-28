package rainspub

import (
	"rains/rainslib"
	"rains/utils/zoneFileParser"
	"testing"
)

func TestLoadAssertions(t *testing.T) {
	config = rainpubConfig{}
	parser = zoneFileParser.Parser{}
	var tests = []struct {
		input  string
		output []*rainslib.AssertionSection
		errMsg string
	}{
		{"test/chZoneFile.txt", []*rainslib.AssertionSection{
			&rainslib.AssertionSection{SubjectName: "ch", SubjectZone: "ch", Context: ".",
				Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP4Addr, Value: "178.209.53.76"}}},
			&rainslib.AssertionSection{SubjectName: "ethz", SubjectZone: "ch", Context: ".",
				Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
					rainslib.Object{Type: rainslib.OTIP4Addr, Value: "178.209.53.76"}}},
		}, ""},
		{"notExist/zonePrivate.key", nil, "open notExist/zonePrivate.key: no such file or directory"},
		{"test/malformed.conf", nil, "ZoneFile malformed wrong section type"},
	}
	for i, test := range tests {
		config.ZoneFilePath = test.input
		assertions, err := loadAssertions()
		if err != nil && err.Error() != test.errMsg {
			t.Errorf("%d: loadAssertions() wrong error message. expected=%s, actual=%s", i, test.errMsg, err.Error())
		}
		if err == nil {
			for j, a := range assertions {
				rainslib.CheckAssertion(a, test.output[j], t)
			}
		}
	}
}

func TestGroupAssertionsToShards(t *testing.T) {
	config = rainpubConfig{}
	a1 := &rainslib.AssertionSection{SubjectName: "ch", SubjectZone: "ch", Context: ".",
		Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP4Addr, Value: "178.209.53.76"}}}
	a2 := &rainslib.AssertionSection{SubjectName: "ethz", SubjectZone: "ch", Context: ".",
		Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
			rainslib.Object{Type: rainslib.OTIP4Addr, Value: "129.132.128.139"}}}
	a3 := &rainslib.AssertionSection{SubjectName: "uzh", SubjectZone: "ch", Context: ".",
		Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP4Addr, Value: "130.60.184.132"}}}
	var tests = []struct {
		input              []*rainslib.AssertionSection
		assertionsPerShard uint
		output             *rainslib.ZoneSection
	}{
		{[]*rainslib.AssertionSection{a1, a2}, 2,
			&rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{
				&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "",
					Content: []*rainslib.AssertionSection{a1, a2}}}}},
		{[]*rainslib.AssertionSection{a2, a1}, 2, //test that sorting works
			&rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{
				&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "",
					Content: []*rainslib.AssertionSection{a1, a2}}}}},
		{[]*rainslib.AssertionSection{a3, a2, a1}, 2, //correct grouping with 2 shards and sorting
			&rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{
				&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "uzh",
					Content: []*rainslib.AssertionSection{a1, a2}},
				&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "ethz", RangeTo: "",
					Content: []*rainslib.AssertionSection{a3}}}}},
	}
	for _, test := range tests {
		config.MaxAssertionsPerShard = test.assertionsPerShard
		rainslib.CheckZone(groupAssertionsToShards(test.input), test.output, t)
	}
}
