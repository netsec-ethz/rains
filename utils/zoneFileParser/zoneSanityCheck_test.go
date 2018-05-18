package zoneFileParser

import (
	"strings"
	"testing"
)

func TestValidateZoneRedirects(t *testing.T) {
	p := Parser{}
	valid := ":Z: . . [ :A: example [ :redir: nic.example. ] :A: nic.example [ :srv: ns1.example. 2345 10 ] :A: ns1.example [ :ip4: 127.0.0.1 ] ]"
	as, err := p.Decode([]byte(valid))
	if err != nil {
		t.Fatalf("malformed zonefile 'valid' hardcoded in test: %v", err)
	}
	if err := ValidateZoneRedirects(as); err != nil {
		t.Errorf("expected no errors for valid zonefile but got %v", err)
	}
	missingTarget := ":Z: . . [ :A: example [ :redir: nic.example. ] :A: nic.example [ :srv: ns1.example. 2345 10 ] ]"
	as, err = p.Decode([]byte(missingTarget))
	if err != nil {
		t.Fatalf("malformed zonefile 'missingTarget' hardcoded in test: %v", err)
	}
	expectErrPrefix := "could not resolve redirect for name"
	if err := ValidateZoneRedirects(as); !strings.HasPrefix(err.Error(), expectErrPrefix) {
		t.Errorf("mismatched error in validateZoneRedirects, got %q, want prefix %q", err.Error(), expectErrPrefix)
	}
	loopTarget := ":Z: . . [ :A: example [ :redir: nic.example. ] :A: nic.example [ :redir: example. ] ]"
	as, err = p.Decode([]byte(loopTarget))
	if err != nil {
		t.Fatalf("malformed zonefile 'loopTarget' hardcoded in test: %v", err)
	}
	expectErrPrefix = "redirect loop for key"
	if err := ValidateZoneRedirects(as); !strings.HasPrefix(err.Error(), expectErrPrefix) {
		t.Errorf("mismatched error in validateZoneRedirects, got %q, want prefix %q", err.Error(), expectErrPrefix)
	}
}
