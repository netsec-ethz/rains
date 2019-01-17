package section

import (
	"testing"
)

func TestIntersect(t *testing.T) {
	var tests = []struct {
		i1        Interval
		i2        Interval
		intersect bool
	}{
		//Points
		{StringInterval{"a"}, StringInterval{"a"}, true},
		{StringInterval{"a"}, StringInterval{"b"}, false},
		//"" represents the start and end of the name space. A point cannot be there. Undefined
		//behavior where our code returns true.
		{StringInterval{""}, StringInterval{""}, true},
		{StringInterval{""}, StringInterval{"b"}, true},
		{StringInterval{"b"}, StringInterval{""}, true},
		//Intervals and Point
		{&Shard{RangeFrom: "a", RangeTo: "b"}, StringInterval{"a"}, false},
		{&Shard{RangeFrom: "a", RangeTo: "b"}, StringInterval{"b"}, false},
		{&Shard{RangeFrom: "a", RangeTo: "b"}, StringInterval{"c"}, false},
		{&Shard{RangeFrom: "a", RangeTo: "b"}, StringInterval{"aa"}, true},
		{&Shard{RangeFrom: "", RangeTo: "b"}, StringInterval{"c"}, false},
		{&Shard{RangeFrom: "b", RangeTo: ""}, StringInterval{"a"}, false},
		{&Shard{RangeFrom: "", RangeTo: "b"}, StringInterval{"a"}, true},
		{&Shard{RangeFrom: "b", RangeTo: ""}, StringInterval{"z"}, true},
		//Intervals
		{&Shard{RangeFrom: "a", RangeTo: "b"}, &Shard{RangeFrom: "a", RangeTo: "b"}, true},
		{&Shard{RangeFrom: "a", RangeTo: "b"}, &Shard{RangeFrom: "b", RangeTo: "c"}, false},
		{&Shard{RangeFrom: "b", RangeTo: "c"}, &Shard{RangeFrom: "a", RangeTo: "b"}, false},
		{&Shard{RangeFrom: "a", RangeTo: "c"}, &Shard{RangeFrom: "b", RangeTo: "d"}, true},
		{&Shard{RangeFrom: "b", RangeTo: "d"}, &Shard{RangeFrom: "a", RangeTo: "c"}, true},
		{&Shard{RangeFrom: "a", RangeTo: "d"}, &Shard{RangeFrom: "b", RangeTo: "c"}, true},
		{&Shard{RangeFrom: "b", RangeTo: "c"}, &Shard{RangeFrom: "a", RangeTo: "d"}, true},
	}
	for i, test := range tests {
		if Intersect(test.i1, test.i2) != test.intersect {
			t.Errorf("%d: Unexpected intersection. expected=%v, actual=%v", i, test.intersect,
				Intersect(test.i1, test.i2))
		}
	}
}
