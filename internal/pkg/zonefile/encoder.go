package zonefile

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
)

// encodeMessage returns a rains message as a string in signable format (which resembles the zone file format)
func encodeMessage(m *message.Message) string {
	return fmt.Sprintf(":M: %s %s [\n%s\n]", encodeCapabilities(m.Capabilities), m.Token.String(), IO{}.Encode(m.Content))
}

// encodeQuery returns an encoding which resembles the zone file format
func encodeQuery(q *query.Name) string {
	return fmt.Sprintf(":Q: %s %s %s %d %s", q.Context, q.Name, encodeObjectTypes(q.Types),
		q.Expiration, encodeQueryOptions(q.Options))
}

// encodeNotification returns a notification in signable format (which resembles the zone file format)
func encodeNotification(n *section.Notification) string {
	return fmt.Sprintf(":N: %s %s %s", n.Token.String(), strconv.Itoa(int(n.Type)), n.Data)
}

// encodeCapabilities returns capabilities separated by space in signable format (which resembles the zone file format)
func encodeCapabilities(caps []message.Capability) string {
	encodedCaps := make([]string, len(caps))
	for i, capa := range caps {
		encodedCaps[i] = string(capa)
	}
	return fmt.Sprintf("[ %s ]", strings.Join(encodedCaps, " "))
}

// encodeQueryOptions returns query options separated by space in signable format (which resembles the zone file format)
func encodeQueryOptions(qopts []query.Option) string {
	encodedQO := make([]string, len(qopts))
	for i, qopt := range qopts {
		encodedQO[i] = strconv.Itoa(int(qopt))
	}
	return fmt.Sprintf("[ %s ]", strings.Join(encodedQO, " "))
}

// encodeObjectTypes returns query connection separated by space in signable format (which resembles the zone file format)
func encodeObjectTypes(objs []object.Type) string {
	encodedOT := make([]string, len(objs))
	for i, objType := range objs {
		encodedOT[i] = strconv.Itoa(int(objType))
	}
	return fmt.Sprintf("[ %s ]", strings.Join(encodedOT, " "))
}
