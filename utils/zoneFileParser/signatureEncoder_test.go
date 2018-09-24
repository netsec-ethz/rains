package parser

import (
	"testing"

	"github.com/netsec-ethz/rains/rainslib"
)

func TestEncodeAddressAssertion(t *testing.T) {
	assertions, encodings := getAddressAssertionsAndEncodings()
	for i, assertion := range assertions {
		encodedAA := encodeAddressAssertion(assertion)
		if encodedAA != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedAA)
		}
	}
}

func TestEncodeAddressQuery(t *testing.T) {
	queries, encodings := getAddressQueriesAndEncodings()
	for i, query := range queries {
		encodedAQ := encodeAddressQuery(query)
		if encodedAQ != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedAQ)
		}
	}
}

func TestEncodeQuery(t *testing.T) {
	queries, encodings := getQueriesAndEncodings()
	for i, query := range queries {
		encodedQ := encodeQuery(query)
		if encodedQ != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedQ)
		}
	}
}

func TestEncodeNotification(t *testing.T) {
	notifications, encodings := getNotificationsAndEncodings()
	for i, notification := range notifications {
		encodedN := encodeNotification(notification)
		if encodedN != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedN)
		}
	}
}

func TestMessageEncoding(t *testing.T) {
	messages, encodings := getMessagesAndEncodings()
	for i, message := range messages {
		encodedM := encodeMessage(message)
		if encodedM != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedM)
		}
	}
}

func TestEncodeCapabilities(t *testing.T) {
	var tests = []struct {
		input []rainslib.Capability
		want  string
	}{
		{[]rainslib.Capability{rainslib.Capability("capa1")}, "[ capa1 ]"},
		{[]rainslib.Capability{rainslib.Capability("capa1"), rainslib.Capability("capa2")}, "[ capa1 capa2 ]"},
	}
	for _, test := range tests {
		if encodeCapabilities(test.input) != test.want {
			t.Errorf("Encoding incorrect. expected=%s, actual=%s", test.want, encodeCapabilities(test.input))
		}
	}
}
