package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/netsec-ethz/rains/rainslib"
)

func TestEncodeDecode(t *testing.T) {
	zones, _ := getZonesAndEncodings()

	parser := Parser{}
	zoneFile := parser.Encode(zones[0])

	assertions, err := parser.Decode([]byte(zoneFile), "generatedInTest")
	if err != nil {
		t.Error(err)
	}

	containedAssertions := []*rainslib.AssertionSection{zones[0].Content[0].(*rainslib.AssertionSection), zones[0].Content[1].(*rainslib.ShardSection).Content[0]}
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
		input rainslib.MessageSection
		want  string
	}{
		{rainslib.MessageSection(&rainslib.Object{}), ""},
	}
	for _, test := range tests {
		if getEncoding(test.input, true) != test.want {
			t.Errorf("Encoding incorrect. expected=%v, actual=%s", test.want, getEncoding(test.input, true))
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
	assertion := &rainslib.AssertionSection{
		Content:     []rainslib.Object{rainslib.Object{Type: rainslib.OTIP4Addr, Value: "127.0.0.1"}},
		SubjectName: "ethz",
	}
	var tests = []struct {
		input rainslib.MessageSection
		want  string
	}{
		{assertion, ":A: ethz [ :ip4: 127.0.0.1 ]"},
	}
	p := Parser{}
	for _, test := range tests {
		if p.EncodeSection(test.input) != test.want {
			t.Errorf("parser.EncodeSection() incorrect. expected=%s, actual=%s", test.want, p.EncodeSection(test.input))
		}
	}
}

func TestEncodeMessage(t *testing.T) {
	assertion := &rainslib.AssertionSection{
		Content:     []rainslib.Object{rainslib.Object{Type: rainslib.OTIP4Addr, Value: "127.0.0.1"}},
		SubjectName: "ethz",
	}
	token := rainslib.GenerateToken()
	capabilities := []rainslib.Capability{rainslib.Capability("capa1"), rainslib.Capability("capa2")}
	encodedToken := hex.EncodeToString(token[:])
	message := &rainslib.RainsMessage{
		Capabilities: capabilities,
		Token:        token,
		Content:      []rainslib.MessageSection{assertion},
	}
	var tests = []struct {
		input *rainslib.RainsMessage
		want  string
	}{
		{message, fmt.Sprintf(":M: [ capa1 capa2 ] %s [ :A: ethz [ :ip4: 127.0.0.1 ] ]", encodedToken)},
	}
	p := Parser{}
	for _, test := range tests {
		if p.EncodeMessage(test.input) != test.want {
			t.Errorf("parser.EncodeSection() incorrect. expected=%s, actual=%s", test.want, p.EncodeMessage(test.input))
		}
	}
}
