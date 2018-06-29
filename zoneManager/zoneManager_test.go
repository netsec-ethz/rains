package main

import (
	"testing"

	"github.com/netsec-ethz/rains/rainslib"
)

func TestGroupAssertionsToShards(t *testing.T) {
	a1 := &rainslib.AssertionSection{SubjectName: "ch", SubjectZone: "ch", Context: ".",
		Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP4Addr, Value: "178.209.53.76"}}}
	a2 := &rainslib.AssertionSection{SubjectName: "ethz", SubjectZone: "ch", Context: ".",
		Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
			rainslib.Object{Type: rainslib.OTIP4Addr, Value: "129.132.128.139"}}}
	a3 := &rainslib.AssertionSection{SubjectName: "uzh", SubjectZone: "ch", Context: ".",
		Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP4Addr, Value: "130.60.184.132"}}}
	var tests = []struct {
		input              []*rainslib.AssertionSection
		assertionsPerShard int
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
		{[]*rainslib.AssertionSection{a3, a2, a1}, 1, //correct grouping with >2 shards and sorting
			&rainslib.ZoneSection{SubjectZone: "ch", Context: ".", Content: []rainslib.MessageSectionWithSigForward{
				&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "", RangeTo: "ethz",
					Content: []*rainslib.AssertionSection{a1}},
				&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "ch", RangeTo: "uzh",
					Content: []*rainslib.AssertionSection{a2}},
				&rainslib.ShardSection{SubjectZone: "ch", Context: ".", RangeFrom: "ethz", RangeTo: "",
					Content: []*rainslib.AssertionSection{a3}}}}},
	}
	for _, test := range tests {
		rainslib.CheckZone(groupAssertionsToShards(test.input[0].SubjectZone,
			test.input[0].Context, test.input), test.output, t)
	}
}

func getAssertionWithTwoIPObjects() *rainslib.AssertionSection {
	return &rainslib.AssertionSection{SubjectName: "ethz", SubjectZone: "ch", Context: ".",
		Content: []rainslib.Object{rainslib.Object{Type: rainslib.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
			rainslib.Object{Type: rainslib.OTIP4Addr, Value: "129.132.128.139"}}}
}
