package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"net"
	"rains/rainslib"

	"golang.org/x/crypto/ed25519"
)

//getQueriesAndEncodings returns a slice of queries and a slice of their encodings used for testing
func getQueriesAndEncodings() ([]*rainslib.QuerySection, []string) {
	//addressqueries
	queries := []*rainslib.QuerySection{}
	token := rainslib.GenerateToken()
	encodedToken := hex.EncodeToString(token[:])
	query := &rainslib.QuerySection{
		Context: ".",
		Expires: 159159,
		Name:    "ethz.ch",
		Options: []rainslib.QueryOption{rainslib.QOMinE2ELatency, rainslib.QOMinInfoLeakage},
		Token:   token,
		Type:    rainslib.OTIP4Addr,
	}
	queries = append(queries, query)

	//encodings
	encodings := []string{}
	encodings = append(encodings, fmt.Sprintf(":Q: %s . ethz.ch [ 3 ] 159159 [ 1 3 ]", encodedToken))

	return queries, encodings
}

//getAddressAssertionsAndEncodings returns a slice of address assertins and a slice of their encodings used for testing
func getAddressAssertionsAndEncodings() ([]*rainslib.AddressAssertionSection, []string) {
	//addressAssertions
	addressAssertions := []*rainslib.AddressAssertionSection{}
	nameObjectContent := rainslib.NameObject{
		Name:  "ethz2.ch",
		Types: []rainslib.ObjectType{rainslib.OTIP4Addr, rainslib.OTIP6Addr},
	}
	publicKey := rainslib.PublicKey{
		KeySpace:   rainslib.RainsKeySpace,
		Type:       rainslib.Ed25519,
		Key:        ed25519.PublicKey([]byte("01234567890123456789012345678901")),
		ValidSince: 10000,
		ValidUntil: 50000,
	}
	nameObject := rainslib.Object{Type: rainslib.OTName, Value: nameObjectContent}
	redirObject := rainslib.Object{Type: rainslib.OTRedirection, Value: "ns.ethz.ch"}
	delegObject := rainslib.Object{Type: rainslib.OTDelegation, Value: publicKey}
	registrantObject := rainslib.Object{Type: rainslib.OTRegistrant, Value: "Registrant information"}

	signature := rainslib.Signature{
		KeySpace:   rainslib.RainsKeySpace,
		Algorithm:  rainslib.Ed25519,
		ValidSince: 1000,
		ValidUntil: 2000,
		Data:       []byte("SignatureData")}

	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	_, subjectAddress2, _ := net.ParseCIDR("127.0.0.1/24")
	_, subjectAddress3, _ := net.ParseCIDR("2001:db8::/128")
	addressAssertion1 := &rainslib.AddressAssertionSection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Content:     []rainslib.Object{nameObject},
		Signatures:  []rainslib.Signature{signature},
	}
	addressAssertion2 := &rainslib.AddressAssertionSection{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     []rainslib.Object{redirObject, delegObject, registrantObject},
		Signatures:  []rainslib.Signature{signature},
	}
	addressAssertion3 := &rainslib.AddressAssertionSection{
		SubjectAddr: subjectAddress3,
		Context:     ".",
		Content:     []rainslib.Object{nameObject},
		Signatures:  []rainslib.Signature{signature},
	}
	addressAssertions = append(addressAssertions, addressAssertion1)
	addressAssertions = append(addressAssertions, addressAssertion2)
	addressAssertions = append(addressAssertions, addressAssertion3)

	//encodings
	encodings := []string{}
	encodings = append(encodings, ":AA: ip4 127.0.0.1/32 . [ :name:     ethz2.ch [ ip4 ip6 ] ]")
	encodings = append(encodings, ":AA: ip4 127.0.0.0/24 . [ :redir:    ns.ethz.ch\n:deleg:    ed25519 3031323334353637383930313233343536373839303132333435363738393031\n:regt:     Registrant information ]")
	encodings = append(encodings, ":AA: ip6 20010db8000000000000000000000000/128 . [ :name:     ethz2.ch [ ip4 ip6 ] ]")

	return addressAssertions, encodings
}

//getAddressZonesAndEncodings returns a slice of address zones and a slice of their encodings used for testing
func getAddressZonesAndEncodings() ([]*rainslib.AddressZoneSection, []string) {
	//addressZones
	addressZones := []*rainslib.AddressZoneSection{}
	assertions, assertionEncodings := getAddressAssertionsAndEncodings()
	addressZone := &rainslib.AddressZoneSection{
		SubjectAddr: assertions[1].SubjectAddr,
		Context:     ".",
		Content:     []*rainslib.AddressAssertionSection{assertions[0], assertions[1], assertions[2]},
		Signatures:  assertions[1].Signatures,
	}
	addressZones = append(addressZones, addressZone)

	//encodings
	encodings := []string{}
	encodings = append(encodings, fmt.Sprintf(":AZ: ip4 127.0.0.0/24 . [ %s %s %s ]", assertionEncodings[0],
		assertionEncodings[1], assertionEncodings[2]))

	return addressZones, encodings
}

//getAddressQueriesAndEncodings returns a slice of address queries and a slice of their encodings used for testing
func getAddressQueriesAndEncodings() ([]*rainslib.AddressQuerySection, []string) {
	//addressqueries
	addressQueries := []*rainslib.AddressQuerySection{}
	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	token := rainslib.GenerateToken()
	encodedToken := hex.EncodeToString(token[:])
	addressQuery := &rainslib.AddressQuerySection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Expires:     7564859,
		Token:       token,
		Type:        rainslib.OTName,
		Options:     []rainslib.QueryOption{rainslib.QOMinE2ELatency, rainslib.QOMinInfoLeakage},
	}
	addressQueries = append(addressQueries, addressQuery)

	//encodings
	encodings := []string{}
	encodings = append(encodings, fmt.Sprintf(":AQ: %s ip4 127.0.0.1/32 . [ 1 ] 7564859 [ 1 3 ]", encodedToken))

	return addressQueries, encodings
}

//getNotificationsAndEncodings returns a slice of notifications and a slice of their encodings used for testing
func getNotificationsAndEncodings() ([]*rainslib.NotificationSection, []string) {
	//addressqueries
	notifications := []*rainslib.NotificationSection{}
	token := rainslib.GenerateToken()
	encodedToken := hex.EncodeToString(token[:])
	notification := &rainslib.NotificationSection{
		Token: token,
		Type:  rainslib.NoAssertionsExist,
		Data:  "Notification information",
	}
	notifications = append(notifications, notification)

	//encodings
	encodings := []string{}
	encodings = append(encodings, fmt.Sprintf(":N: %s 404 Notification information", encodedToken))

	return notifications, encodings
}
