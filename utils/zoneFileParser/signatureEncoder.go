package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"net"
	"rains/rainslib"
	"strconv"
	"strings"
)

func encodeQuery(q *rainslib.QuerySection) string {
	return fmt.Sprintf(":Q: %s %s %s %s %d %s ", q.Token.String(), q.Context, q.Name, encodeObjectTypes([]rainslib.ObjectType{q.Type}),
		q.Expires, encodeQueryOptions(q.Options))
}

func encodeAddressQuery(q *rainslib.AddressQuerySection) string {
	return fmt.Sprintf(":Q: %s %s %s %s %d %s ", q.Token.String(), q.Context, encodeSubjectAddress(q.SubjectAddr),
		encodeObjectTypes([]rainslib.ObjectType{q.Types}), q.Expires, encodeQueryOptions(q.Options))
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
