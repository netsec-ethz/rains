package zonefile

import (
	"testing"

	"github.com/netsec-ethz/rains/internal/pkg/message"
)

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
	//FIXME
	/*messages, encodings := getMessagesAndEncodings()
	for i, message := range messages {
		encodedM := encodeMessage(message)
		if encodedM != encodings[i] {
			t.Errorf("Encoding wrong. expected=%s actual=%s", encodings[i], encodedM)
		}
	}*/
}

func TestEncodeCapabilities(t *testing.T) {
	var tests = []struct {
		input []message.Capability
		want  string
	}{
		{[]message.Capability{message.Capability("capa1")}, "[ capa1 ]"},
		{[]message.Capability{message.Capability("capa1"), message.Capability("capa2")}, "[ capa1 capa2 ]"},
	}
	for _, test := range tests {
		if encodeCapabilities(test.input) != test.want {
			t.Errorf("Encoding incorrect. expected=%s, actual=%s", test.want, encodeCapabilities(test.input))
		}
	}
}
