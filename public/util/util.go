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

var (
	addrRegexp = regexp.MustCompile(`(?P<ia>\d+-[\d:A-Fa-f]+),\[(?P<host>[^\]]+)\]`)
	context    = "."
	timeout    = time.Second
)

// QueryName queries the RAINS server at 'addr' for 'name' and returns the raw Assertions corresponding to 'types'
// 'addr' must either be a *snet.Addr or *net.TCPAddr
func QueryName(name, types, addr string, port uint16) (*message.Message, error) {
	var serverAddr net.Addr
	serverAddr, err := snet.AddrFromString(fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		// Not a valid SCION address, try to parse it as a regular IP address
		serverAddr, err = net.ResolveTCPAddr("", fmt.Sprintf("%s:%d", addr, port))
		if err != nil {
			return nil, err
		}
	}

	var qTypes []object.Type
	var opts []query.Option // TODO (chaehni): take options as argument
	token := token.New()

	qTypes, err = object.ParseTypes(types)
	if err != nil {
		return nil, err
	}

	msg := util.NewQueryMessage(name, context, time.Now().Add(timeout).Unix(), qTypes, opts, token)
	reply, err := util.SendQuery(msg, serverAddr, time.Second)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}

// FormatSections formats []section.Section according to the zone file format
func FormatSections(sections []section.Section) string {
	return zonefile.IO{}.Encode(sections)
}

// ParseSCIONAddr returns the SCION address contained in an Assertion
func ParseSCIONAddr(assertion *message.Message) (string, error) {
	parsed := addrRegexp.FindString(FormatSections(assertion.Content))
	if parsed == "" {
		return "", fmt.Errorf("Assertion does not contain SCION address")
	}
	return parsed, nil
}
