package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/netsec-ethz/rains/rainslib"
)

//encodeMessage returns a rains message as a string in signable format (which resembles the zone file format)
func encodeMessage(m *rainslib.RainsMessage) string {
	content := []string{}
	for _, section := range m.Content {
		content = append(content, getEncoding(section, true))
	}
	return fmt.Sprintf(":M: %s %s [\n%s\n]", encodeCapabilities(m.Capabilities), m.Token.String(), strings.Join(content, "\n"))
}

//encodeAddressAssertion returns an address assertion in signable format (which resembles the zone file format)
func encodeAddressAssertion(a *rainslib.AddressAssertionSection) string {
	return fmt.Sprintf(":AA: %s %s [ %s ]", encodeSubjectAddress(a.SubjectAddr), a.Context, encodeObjects(a.Content, ""))
}

//encodeAddressZone returns an address zone in signable format (which resembles the zone file format)
func encodeAddressZone(z *rainslib.AddressZoneSection) string {
	assertions := make([]string, len(z.Content))
	for i, a := range z.Content {
		assertions[i] = encodeAddressAssertion(a)
	}
	return fmt.Sprintf(":AZ: %s %s [ %s ]", encodeSubjectAddress(z.SubjectAddr), z.Context, strings.Join(assertions, " "))
}

//encodeAddressQuery returns an address query in signable format (which resembles the zone file format)
func encodeAddressQuery(q *rainslib.AddressQuerySection) string {
	return fmt.Sprintf(":AQ: %s %s %s %d %s", encodeSubjectAddress(q.SubjectAddr), q.Context,
		encodeObjectTypes([]rainslib.ObjectType{q.Type}), q.Expires, encodeQueryOptions(q.Options))
}

//encodeQuery returns a query in signable format (which resembles the zone file format)
func encodeQuery(q *rainslib.QuerySection) string {
	return fmt.Sprintf(":Q: %s %s %s %d %s", q.Context, q.Name, encodeObjectTypes([]rainslib.ObjectType{q.Type}),
		q.Expires, encodeQueryOptions(q.Options))
}

//encodeNotification returns a notification in signable format (which resembles the zone file format)
func encodeNotification(n *rainslib.NotificationSection) string {
	return fmt.Sprintf(":N: %s %s %s", n.Token.String(), strconv.Itoa(int(n.Type)), n.Data)
}

//encodeCapabilities returns capabilities separated by space in signable format (which resembles the zone file format)
func encodeCapabilities(caps []rainslib.Capability) string {
	encodedCaps := make([]string, len(caps))
	for i, capa := range caps {
		encodedCaps[i] = string(capa)
	}
	return fmt.Sprintf("[ %s ]", strings.Join(encodedCaps, " "))
}

//encodeQueryOptions returns query options separated by space in signable format (which resembles the zone file format)
func encodeQueryOptions(qopts []rainslib.QueryOption) string {
	encodedQO := make([]string, len(qopts))
	for i, qopt := range qopts {
		encodedQO[i] = strconv.Itoa(int(qopt))
	}
	return fmt.Sprintf("[ %s ]", strings.Join(encodedQO, " "))
}

//encodeObjectTypes returns query types separated by space in signable format (which resembles the zone file format)
func encodeObjectTypes(objs []rainslib.ObjectType) string {
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
		return fmt.Sprintf("%s %s", otIP4, addr.String())
	}
	//IP6
	prfLength, _ := addr.Mask.Size()
	return fmt.Sprintf("%s %s/%d", otIP6, hex.EncodeToString([]byte(addr.IP)), prfLength)
}
