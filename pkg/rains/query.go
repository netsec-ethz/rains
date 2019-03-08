package rains

import (
	"fmt"
	"net"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
)

// Message carries the reply received from the a RAINS server
type Message struct {

	// embedded message type
	msg message.Message
}

// ParseMessage parses the message and returns a map mapping all object types found in the assertion to their value
func (m *Message) ParseMessage() (map[Type]string, error) {

	// we expect exactly one section, an assertion
	if len(m.msg.Content) != 1 {
		return nil, fmt.Errorf("message contains invalid number of sections")
	}

	assertion, ok := m.msg.Content[0].(*section.Assertion)
	if !ok {
		return nil, fmt.Errorf("message is not an assertion")
	}

	vals := make(map[Type]string)
	for _, cont := range assertion.Content {
		vals[Type(cont.Type)] = fmt.Sprintf("%v", cont.Value)
	}

	return vals, nil
}

func (m *Message) String() string {
	return formatSections(m.msg.Content)
}

// Query queries the RAINS server at addr for name and returns a map of values
// each corresponding to a type requested by types
func Query(name, context string, types []Type, opts []Option,
	timeout time.Duration, addr net.Addr) (map[Type]string, error) {

	raw, err := QueryRaw(name, context, types, opts, timeout, addr)
	if err != nil {
		return nil, err
	}
	res, err := raw.ParseMessage()
	if err != nil {
		return nil, err
	}

	return res, nil
}

// QueryRaw queries the RAINS server at addr for name and returns the raw reply
func QueryRaw(name, context string, types []Type, opts []Option,
	timeout time.Duration, addr net.Addr) (Message, error) {

	token := token.New()
	qTypes := convertTyps(types)
	qOpts := convertOpts(opts)

	msg := util.NewQueryMessage(name, context, time.Now().Add(timeout).Unix(), qTypes, qOpts, token)
	reply, err := util.SendQuery(msg, addr, time.Second)
	if err != nil {
		return Message{}, err
	}

	return Message{reply}, nil
}

// formatSections formats sections according to the zone file format
func formatSections(sections []section.Section) string {
	return zonefile.IO{}.Encode(sections)
}
