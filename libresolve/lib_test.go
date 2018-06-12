package libresolve

import (
	"fmt"
	"reflect"
	"testing"
)

// Checks whether the label parsing functionality is as expected.
func TestNameToLabels(t *testing.T) {
	badInput := "www.department.corp.jp"
	expectedErr := fmt.Errorf("domain name must end with root qualifier '.', got %s", badInput)
	res, err := NameToLabels(badInput)
	if err.Error() != expectedErr.Error() {
		t.Errorf("mismatched errors: want %v, got %v", expectedErr, err)
	}
	if res != nil {
		t.Errorf("expected nil response but got %v", res)
	}
	goodInput := "www.post.ch."
	expected := []string{"www", "post", "ch"}
	res, err = NameToLabels(goodInput)
	if err != nil {
		t.Errorf("expected nil error, but got %v", err)
	}
	if !reflect.DeepEqual(res, expected) {
		t.Errorf("mismatched return value, got %v, want %v", res, expected)
	}
}
