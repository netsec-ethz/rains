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
			encoding += fmt.Sprintf(":Q: %s %s %s %s %d %s ", s.Token.String(), s.Context, s.Name, encodeObjectTypes([]rainslib.ObjectType{s.Type}),
				s.Expires, encodeQueryOptions(s.Options))
		case *rainslib.NotificationSection:
			encoding += fmt.Sprintf(":N: %s %s %s ", s.Token.String(), strconv.Itoa(int(s.Type)), s.Data)
		case *rainslib.AddressAssertionSection:
			encoding += EncodeAddressAssertion(s) + " "
		case *rainslib.AddressZoneSection:
			encoding += EncodeAddressZone(s) + " "
		case *rainslib.AddressQuerySection:
			encoding += fmt.Sprintf(":AQ: %s %s %s %s %d %s ", s.Token.String(), s.Context, encodeSubjectAddress(s.SubjectAddr),
				encodeObjectTypes([]rainslib.ObjectType{s.Types}), s.Expires, encodeQueryOptions(s.Options))
		default:
			log.Warn("Unsupported section type", "type", fmt.Sprintf("%T", s))
			return ""
		}
	}
	return encoding
}

func EncodeAddressAssertion(a *rainslib.AddressAssertionSection) string {
	return ""
}

func EncodeAddressZone(z *rainslib.AddressZoneSection) string {
	return ""
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
