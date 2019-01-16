package query

import (
	"math/rand"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/object"
)

func TestContainsOptions(t *testing.T) {
	var tests = []struct {
		input []Option
		param Option
		want  bool
	}{
		{[]Option{QOCachedAnswersOnly, QOExpiredAssertionsOk}, QOCachedAnswersOnly, true},
		{[]Option{QOCachedAnswersOnly, QOExpiredAssertionsOk}, QOExpiredAssertionsOk, true},
		{[]Option{}, QOCachedAnswersOnly, false},
		{[]Option{QOExpiredAssertionsOk}, QOCachedAnswersOnly, false},
	}
	for i, test := range tests {
		if containsOption(test.param, test.input) != test.want {
			t.Errorf("%d: containsOptions response incorrect. expected=%v, actual=%v", i, test.want, containsOption(test.param, test.input))
		}
		query := &Name{Options: test.input}
		if query.ContainsOption(test.param) != test.want {
			t.Errorf("%d: ContainsOptions response incorrect. expected=%v, actual=%v", i, test.want, containsOption(test.param, test.input))
		}
	}
}

func TestQuerySort(t *testing.T) {
	var tests = []struct {
		input  []Option
		sorted []Option
	}{
		{[]Option{Option(5), Option(3)}, []Option{Option(3), Option(5)}},
	}
	for i, test := range tests {
		q := &Name{Options: test.input}
		q.Sort()
		if !reflect.DeepEqual(q.Options, test.sorted) {
			t.Errorf("%d: Sort() does not sort correctly expected=%v actual=%v", i, test.sorted, q.Options)
		}
	}
}

func TestQueryCompareTo(t *testing.T) {
	queries := sortedQueries(5)
	var shuffled []*Name
	for _, q := range queries {
		shuffled = append(shuffled, q)
	}
	shuffleQueries(shuffled)
	sort.Slice(shuffled, func(i, j int) bool {
		return shuffled[i].CompareTo(shuffled[j]) < 0
	})
	for i, q := range queries {
		checkQuery(q, shuffled[i], t)
	}
}

func shuffleQueries(queries []*Name) {
	for i := len(queries) - 1; i > 0; i-- {
		j := rand.Intn(i)
		queries[i], queries[j] = queries[j], queries[i]
	}
}

func sortedQueries(nof int) []*Name {
	queries := []*Name{}
	for i := 0; i < nof; i++ {
		for j := 0; j < nof; j++ {
			for k := 0; k < 13; k++ {
				for l := 0; l < nof; l++ {
					for m := 0; m < 8; m++ {
						//TODO CFE extend this test when we support multiple connection per assertion
						queries = append(queries, &Name{
							Context:    strconv.Itoa(i),
							Name:       strconv.Itoa(j),
							Types:      []object.Type{object.Type(k)},
							Expiration: int64(l),
							Options:    []Option{Option(m)},
						})
					}
					for m := 0; m < 7; m++ {
						for n := m + 1; n < 8; n++ {
							//TODO CFE extend this test when we support multiple connection per assertion
							queries = append(queries, &Name{
								Context:    strconv.Itoa(i),
								Name:       strconv.Itoa(j),
								Types:      []object.Type{object.Type(k)},
								Expiration: int64(l),
								Options:    []Option{Option(m), Option(n)},
							})
						}
					}
				}
			}
		}
	}
	queries = append(queries, queries[len(queries)-1])
	return queries
}

func checkQuery(q1, q2 *Name, t *testing.T) {
	if q1.Context != q2.Context {
		t.Error("Query context mismatch")
	}
	if q1.Expiration != q2.Expiration {
		t.Error("Query Expires mismatch")
	}
	if q1.Name != q2.Name {
		t.Error("Query Name mismatch")
	}
	if len(q1.Types) != len(q2.Types) {
		t.Error("Query Type length mismatch")
	}
	for i, o1 := range q1.Types {
		if o1 != q2.Types[i] {
			t.Errorf("Query Type at position %d mismatch", i)
		}
	}
	if len(q1.Options) != len(q2.Options) {
		t.Error("Query Option length mismatch")
	}
	for i, o1 := range q1.Options {
		if o1 != q2.Options[i] {
			t.Errorf("Query Option at position %d mismatch", i)
		}
	}
}
