package token

import (
	"testing"
)

func TestGenerateToken(t *testing.T) {
	t1 := New()
	t2 := New()
	if t1 == t2 {
		t.Errorf("Subsequent generated tokens should not have the same value t1=%s t2=%s", t1, t2)
	}
}
