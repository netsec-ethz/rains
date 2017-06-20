package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"net"
	"rains/rainslib"
	"strconv"
	"strings"
)

//encodeMessage transforms a rains message into a signable format
func encodeMessage(m *rainslib.RainsMessage) string {
	encoding := fmt.Sprintf(":M: %s %s ", encodeCapabilities(m.Capabilities), m.Token.String())
	for _, section := range m.Content {
		encoding += getEncoding(section, true) + " "
	}
	return encoding
}

//encodeAddressAssertion transforms an address assertion into a signable format
func encodeAddressAssertion(a *rainslib.AddressAssertionSection) string {
	return fmt.Sprintf(":AA: %s %s [ %s ]", encodeSubjectAddress(a.SubjectAddr), a.Context, encodeObjects(a.Content, ""))
}

//encodeAddressZone transforms an address zone into a signable format
func encodeAddressZone(z *rainslib.AddressZoneSection) string {
	assertions := make([]string, len(z.Content))
	for i, a := range z.Content {
		assertions[i] = encodeAddressAssertion(a)
	}
	return fmt.Sprintf(":AZ: %s %s [ %s ]", encodeSubjectAddress(z.SubjectAddr), z.Context, strings.Join(assertions, " "))
}

func encodeAddressQuery(q *rainslib.AddressQuerySection) string {
	return fmt.Sprintf(":AQ: %s %s %s %s %d %s", q.Token.String(), encodeSubjectAddress(q.SubjectAddr), q.Context,
		encodeObjectTypes([]rainslib.ObjectType{q.Type}), q.Expires, encodeQueryOptions(q.Options))
}

func encodeQuery(q *rainslib.QuerySection) string {
	return fmt.Sprintf(":Q: %s %s %s %s %d %s", q.Token.String(), q.Context, q.Name, encodeObjectTypes([]rainslib.ObjectType{q.Type}),
		q.Expires, encodeQueryOptions(q.Options))
}

func encodeNotification(n *rainslib.NotificationSection) string {
	return fmt.Sprintf(":N: %s %s %s", n.Token.String(), strconv.Itoa(int(n.Type)), n.Data)
}

func encodeCapabilities(caps []rainslib.Capability) string {
	encodedCaps := make([]string, len(caps))
	for i, capa := range caps {
		encodedCaps[i] = string(capa)
	}
	return fmt.Sprintf("[ %s ]", strings.Join(encodedCaps, " "))
}

func encodeQueryOptions(qopts []rainslib.QueryOption) string {
	encodedQO := make([]string, len(qopts))
	for i, qopt := range qopts {
		encodedQO[i] = strconv.Itoa(int(qopt))
	}
	return fmt.Sprintf("[ %s ]", strings.Join(encodedQO, " "))
}

func encodeObjectTypes(objs []rainslib.ObjectType) string {
	encodedOT := make([]string, len(objs))
	for i, objType := range objs {
		encodedOT[i] = strconv.Itoa(int(objType))
	}
	return fmt.Sprintf("[ %s ]", strings.Join(encodedOT, " "))
}

func encodeSubjectAddress(addr *net.IPNet) string {
	if addr.IP.To4() != nil {
		//IP4
		return fmt.Sprintf("%s %s", otIP4, addr.String())
	}
	//IP6
	prfLength, _ := addr.Mask.Size()
	return fmt.Sprintf("%s %s/%d", otIP6, hex.EncodeToString([]byte(addr.IP)), prfLength)
}
