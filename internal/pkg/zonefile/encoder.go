package zonefile

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/sections"
)

//encodeMessage returns a rains message as a string in signable format (which resembles the zone file format)
func encodeMessage(m *message.RainsMessage) string {
	content := []string{}
	for _, section := range m.Content {
		content = append(content, GetEncoding(section, true))
	}
	return fmt.Sprintf(":M: %s %s [\n%s\n]", encodeCapabilities(m.Capabilities), m.Token.String(), strings.Join(content, "\n"))
}

//encodeAddressAssertion returns an address assertion in signable format (which resembles the zone file format)
func encodeAddressAssertion(a *sections.AddressAssertionSection) string {
	return fmt.Sprintf(":AA: %s %s [ %s ]", encodeSubjectAddress(a.SubjectAddr), a.Context, encodeObjects(a.Content, ""))
}

//encodeAddressQuery returns an encoding which resembles the zone file format
func encodeAddressQuery(q *sections.AddressQuerySection) string {
	return fmt.Sprintf(":AQ: %s %s %s %d %s", encodeSubjectAddress(q.SubjectAddr), q.Context,
		encodeObjectTypes(q.Types), q.Expiration, encodeQueryOptions(q.Options))
}

//encodeQuery returns an encoding which resembles the zone file format
func encodeQuery(q *sections.QuerySection) string {
	return fmt.Sprintf(":Q: %s %s %s %d %s", q.Context, q.Name, encodeObjectTypes(q.Types),
		q.Expiration, encodeQueryOptions(q.Options))
}

//encodeAssertionUpdateQuery returns an encoding which resembles the zone file format
func encodeAssertionUpdateQuery(q *sections.AssertionUpdateSection) string {
	return fmt.Sprintf(":AUQ: %s %v %s %d %s", q.Name, q.HashType, hex.EncodeToString(q.HashValue),
		q.Expiration, encodeQueryOptions(q.Options))
}

//encodeNonExistenceUpdateQuery returns an encoding which resembles the zone file format
func encodeNonExistenceUpdateQuery(q *sections.NonExistenceUpdateSection) string {
	return fmt.Sprintf(":NUQ: %s %s %s %v %s %d %s", q.Context, q.Name, encodeObjectTypes(q.ObjectTypes),
		q.HashType, hex.EncodeToString(q.HashValue), q.Expiration, encodeQueryOptions(q.Options))
}

//encodeNotification returns a notification in signable format (which resembles the zone file format)
func encodeNotification(n *sections.NotificationSection) string {
	return fmt.Sprintf(":N: %s %s %s", n.Token.String(), strconv.Itoa(int(n.Type)), n.Data)
}

//encodeCapabilities returns capabilities separated by space in signable format (which resembles the zone file format)
func encodeCapabilities(caps []message.Capability) string {
	encodedCaps := make([]string, len(caps))
	for i, capa := range caps {
		encodedCaps[i] = string(capa)
	}
	return fmt.Sprintf("[ %s ]", strings.Join(encodedCaps, " "))
}

//encodeQueryOptions returns query options separated by space in signable format (which resembles the zone file format)
func encodeQueryOptions(qopts []sections.QueryOption) string {
	encodedQO := make([]string, len(qopts))
	for i, qopt := range qopts {
		encodedQO[i] = strconv.Itoa(int(qopt))
	}
	return fmt.Sprintf("[ %s ]", strings.Join(encodedQO, " "))
}

//encodeObjectTypes returns query connection separated by space in signable format (which resembles the zone file format)
func encodeObjectTypes(objs []object.ObjectType) string {
	encodedOT := make([]string, len(objs))
	for i, objType := range objs {
		encodedOT[i] = strconv.Itoa(int(objType))
	}
	return fmt.Sprintf("[ %s ]", strings.Join(encodedOT, " "))
}

//encodeSubjectAddress returns a subjectAddress in signable format (which resembles the zone file format)
func encodeSubjectAddress(addr *net.IPNet) string {
	if addr.IP.To4() != nil {
		//IP4
		return fmt.Sprintf("%s %s", TypeIP4, addr.String())
	}
	//IP6
	prfLength, _ := addr.Mask.Size()
	return fmt.Sprintf("%s %s/%d", TypeIP6, hex.EncodeToString([]byte(addr.IP)), prfLength)
}
