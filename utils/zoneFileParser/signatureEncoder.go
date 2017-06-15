package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"net"
	"rains/rainslib"
	"strconv"
	"strings"

	log "github.com/inconshreveable/log15"
)

//EncodeMessage transforms a rains message into a signable format
func EncodeMessage(m *rainslib.RainsMessage) string {
	encoding := fmt.Sprintf(":M: %s %s ", m.Token.String(), encodeCapabilities(m.Capabilities))
	for _, section := range m.Content {
		switch s := section.(type) {
		case *rainslib.AssertionSection:
			encoding += EncodeAssertion(s, s.Context, s.SubjectZone, "") + " "
		case *rainslib.ShardSection:
			encoding += EncodeShard(s, s.Context, s.SubjectZone, true) + " "
		case *rainslib.ZoneSection:
			encoding += EncodeZone(s, true) + " "
		case *rainslib.QuerySection:
			encoding += encodeQuery(s) + " "
		case *rainslib.NotificationSection:
			encoding += encodeNotification(s) + " "
		case *rainslib.AddressAssertionSection:
			encoding += EncodeAddressAssertion(s) + " "
		case *rainslib.AddressZoneSection:
			encoding += EncodeAddressZone(s) + " "
		case *rainslib.AddressQuerySection:
			encoding += encodeAddressQuery(s) + " "
		default:
			log.Warn("Unsupported section type", "type", fmt.Sprintf("%T", s))
			return ""
		}
	}
	return encoding
}

//EncodeAddressAssertion transforms an address assertion into a signable format
func EncodeAddressAssertion(a *rainslib.AddressAssertionSection) string {
	return fmt.Sprintf(":AA: %s %s [ %s ]", a.Context, encodeSubjectAddress(a.SubjectAddr), encodeObjects(a.Content, ""))
}

//EncodeAddressZone transforms an address zone into a signable format
func EncodeAddressZone(z *rainslib.AddressZoneSection) string {
	assertions := make([]string, len(z.Content))
	for i, a := range z.Content {
		assertions[i] = EncodeAddressAssertion(a)
	}
	return fmt.Sprintf(":AZ: %s %s [ %s ]", z.Context, encodeSubjectAddress(z.SubjectAddr), strings.Join(assertions, " "))
}

func encodeAddressQuery(q *rainslib.AddressQuerySection) string {
	return fmt.Sprintf(":AQ: %s %s %s %s %d %s", q.Token.String(), q.Context, encodeSubjectAddress(q.SubjectAddr),
		encodeObjectTypes([]rainslib.ObjectType{q.Types}), q.Expires, encodeQueryOptions(q.Options))
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
