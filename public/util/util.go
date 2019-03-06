package util

import (
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/internal/pkg/util"
	"github.com/netsec-ethz/rains/internal/pkg/zonefile"
	"github.com/scionproto/scion/go/lib/snet"
)

var scionIP4Addr = regexp.MustCompile(`:scionip4:(?P<addr>\d+-[\d:A-Fa-f]+,\[[^\]]+\])`)

// QueryName queries the RAINS server at addr for name and returns the raw reply for the given type
// addr must either be a *snet.Addr or *net.TCPAddr
func QueryName(name, context string, types []string, opts []int, timeout time.Duration,
	addr string, port uint16) (*message.Message, error) {

	var serverAddr net.Addr
	serverAddr, err := snet.AddrFromString(fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		// Not a valid SCION address, try to parse it as a regular IP address
		serverAddr, err = net.ResolveTCPAddr("", fmt.Sprintf("%s:%d", addr, port))
		if err != nil {
			return nil, err
		}
	}

	token := token.New()
	qOpts := parseQueryOption(opts)
	qTypes := parseTypes(types)
	if err != nil {
		return nil, err
	}

	msg := util.NewQueryMessage(name, context, time.Now().Add(timeout).Unix(), qTypes, qOpts, token)
	reply, err := util.SendQuery(msg, serverAddr, time.Second)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}

// FormatSections formats sections according to the zone file format
func FormatSections(sections []section.Section) string {
	return zonefile.IO{}.Encode(sections)
}

// ParseSCIONAddr returns the SCION address contained in an Assertion
func ParseSCIONAddr(msg *message.Message) (string, error) {
	if len(msg.Content) == 0 {
		return "", fmt.Errorf("message is not an assertion")
	}
	switch msg.Content[0].(type) {
	case *section.Assertion:
		parsed := scionIP4Addr.FindStringSubmatch(FormatSections(msg.Content))
		if len(parsed) == 0 {
			return "", fmt.Errorf("assertion does not contain a SCION address")
		}
		return parsed[1], nil
	default:
		return "", fmt.Errorf("message is not an assertion")
	}
}

// TODO (chaehni) do we need this validity check?
// query.Option is just an int, we could pass the opts slice directly
// Or make RAINS library expose the Options ( same for query Types)
func parseQueryOption(opts []int) []query.Option {
	var qOpts []query.Option
	for _, opt := range opts {
		switch opt {
		case 1:
			qOpts = append(qOpts, query.QOMinE2ELatency)
		case 2:
			qOpts = append(qOpts, query.QOMinLastHopAnswerSize)
		case 3:
			qOpts = append(qOpts, query.QOMinInfoLeakage)
		case 4:
			qOpts = append(qOpts, query.QOCachedAnswersOnly)
		case 5:
			qOpts = append(qOpts, query.QOExpiredAssertionsOk)
		case 6:
			qOpts = append(qOpts, query.QOTokenTracing)
		case 7:
			qOpts = append(qOpts, query.QONoVerificationDelegation)
		case 8:
			qOpts = append(qOpts, query.QONoProactiveCaching)
		case 9:
			qOpts = append(qOpts, query.QOMaxFreshness)
		default:
			continue
		}
	}
	return qOpts
}

func parseTypes(types []string) []object.Type {
	var qTypes []object.Type
	for _, t := range types {
		parsed, err := object.ParseTypes(t)
		if err == nil {
			qTypes = append(qTypes, parsed...)
		}
	}
	return qTypes
}
