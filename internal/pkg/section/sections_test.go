package section

import (
	"reflect"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
)

func TestSigs(t *testing.T) {
	var tests = []struct {
		input  []signature.Sig
		param  keys.KeySpaceID
		output []signature.Sig
	}{
		{[]signature.Sig{signature.Sig{PublicKeyID: keys.PublicKeyID{KeySpace: keys.KeySpaceID(-1)}}, signature.Sig{}}, keys.RainsKeySpace, []signature.Sig{signature.Sig{}}},
	}
	for i, test := range tests {
		var s WithSig
		s = &Assertion{Signatures: test.input}
		sigs := s.Sigs(test.param)
		if !reflect.DeepEqual(sigs, test.output) {
			t.Errorf("%d: assertion.Sigs() does not return the expected signatures expected=%v actual=%v", i, test.output, sigs)
		}
		s = &Shard{Signatures: test.input}
		sigs = s.Sigs(test.param)
		if !reflect.DeepEqual(sigs, test.output) {
			t.Errorf("%d: shard.Sigs() does not return the expected signatures expected=%v actual=%v", i, test.output, sigs)
		}
		s = &Zone{Signatures: test.input}
		sigs = s.Sigs(test.param)
		if !reflect.DeepEqual(sigs, test.output) {
			t.Errorf("%d: zone.Sigs() does not return the expected signatures expected=%v actual=%v", i, test.output, sigs)
		}
	}
}
