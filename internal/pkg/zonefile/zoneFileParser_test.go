package zonefile

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/sections"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

func TestEncodeDecode(t *testing.T) {
	zones, _ := getZonesAndEncodings()

	parser := Parser{}
	zoneFile := parser.Encode(zones[0])

	decode, err := parser.Decode([]byte(zoneFile))
	assertions := []*sections.AssertionSection{}
	for _, a := range decode {
		assertions = append(assertions, a.(*sections.AssertionSection))
	}
	if err != nil {
		t.Error(err)
	}

	containedAssertions := []*sections.AssertionSection{zones[0].Content[0].(*sections.AssertionSection), zones[0].Content[1].(*sections.ShardSection).Content[0]}
	for i, a := range assertions {
		//contained section must not have a context or subjectZone, thus to compare it, inherit the value from the zone
		containedAssertions[i].Context = zones[0].Context
		containedAssertions[i].SubjectZone = zones[0].SubjectZone
		if a != nil && a.CompareTo(containedAssertions[i]) != 0 {
			t.Errorf("incorrect decoding of zone. expected=%v, actual=%v", containedAssertions[i], a)
		}
	}
}

func TestGetEncodingErrors(t *testing.T) {
	var tests = []struct {
		input sections.MessageSection
		want  string
	}{
		{sections.MessageSection(&object.Object{}), ""},
	}
	for _, test := range tests {
		if GetEncoding(test.input, true) != test.want {
			t.Errorf("Encoding incorrect. expected=%v, actual=%s", test.want, GetEncoding(test.input, true))
		}
	}
}

func TestReplaceWhitespaces(t *testing.T) {
	var tests = []struct {
		input string
		want  string
	}{
		//spaces
		{"asdf", "asdf"},
		{"asdf asdf", "asdf asdf"},
		{"asdf   asdf", "asdf asdf"},
		{"   asdf asdf", "asdf asdf"},
		{"asdf asdf   ", "asdf asdf"},
		//tabs
		{"asdf\tasdf", "asdf asdf"},
		{"\tasdf\t asdf", "asdf asdf"},
		{"asdf\t\t\nasdf\t", "asdf asdf"},
		//new lines
		{"asdf \n \n asdf", "asdf asdf"},
		{"asdf   asdf", "asdf asdf"},
		{"\n \nasdf asdf", "asdf asdf"},
		{"asdf asdf \n\n \n  ", "asdf asdf"},
	}
	for _, test := range tests {
		if replaceWhitespaces(test.input) != test.want {
			t.Errorf("Whitespace replacement was incorrect. expected=%s, actual=%s", test.want, replaceWhitespaces(test.input))
		}
	}
}

func TestEncodeSection(t *testing.T) {
	assertion := &sections.AssertionSection{
		Content:     []object.Object{object.Object{Type: object.OTIP4Addr, Value: "127.0.0.1"}},
		SubjectName: "ethz",
	}
	var tests = []struct {
		input sections.MessageSectionWithSigForward
		want  string
	}{
		{assertion, ":A: ethz [ :ip4: 127.0.0.1 ]"},
	}
	p := Parser{}
	for _, test := range tests {
		if string(p.EncodeSection(test.input)) != test.want {
			t.Errorf("parser.EncodeSection() incorrect. expected=%s, actual=%s", test.want, p.EncodeSection(test.input))
		}
	}
}

func TestEncodeMessage(t *testing.T) {
	assertion := &sections.AssertionSection{
		Content:     []object.Object{object.Object{Type: object.OTIP4Addr, Value: "127.0.0.1"}},
		SubjectName: "ethz",
	}
	token := token.GenerateToken()
	capabilities := []message.Capability{message.Capability("capa1"), message.Capability("capa2")}
	encodedToken := hex.EncodeToString(token[:])
	message := &message.RainsMessage{
		Capabilities: capabilities,
		Token:        token,
		Content:      []sections.MessageSection{assertion},
	}
	var tests = []struct {
		input *message.RainsMessage
		want  string
	}{
		{message, fmt.Sprintf(":M: [ capa1 capa2 ] %s [ :A: ethz [ :ip4: 127.0.0.1 ] ]", encodedToken)},
	}
	p := Parser{}
	for _, test := range tests {
		if string(p.EncodeMessage(test.input)) != test.want {
			t.Errorf("parser.EncodeSection() incorrect. expected=%s, actual=%s", test.want, p.EncodeMessage(test.input))
		}
	}
}
