package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"net"
	"rains/rainslib"
	"strings"

	"golang.org/x/crypto/ed25519"
)

//getObjectsAndEncodings returns a slice of options and a slice of their encodings used for testing
func getObjectsAndEncodings() ([]rainslib.Object, []string) {
	//options
	options := []rainslib.Object{}
	nameObjectContent := rainslib.NameObject{
		Name:  "ethz2.ch",
		Types: []rainslib.ObjectType{rainslib.OTIP4Addr, rainslib.OTIP6Addr},
	}
	pubKey, _, _ := ed25519.GenerateKey(nil)
	publicKey := rainslib.PublicKey{
		KeySpace: rainslib.RainsKeySpace,
		Type:     rainslib.Ed25519,
		Key:      pubKey,
	}
	publicKeyWithValidity := rainslib.PublicKey{
		KeySpace:   rainslib.RainsKeySpace,
		Type:       rainslib.Ed25519,
		Key:        pubKey,
		ValidSince: 1000,
		ValidUntil: 20000,
	}
	certificate := rainslib.CertificateObject{
		Type:     rainslib.PTTLS,
		HashAlgo: rainslib.Sha256,
		Usage:    rainslib.CUEndEntity,
		Data:     []byte("certData"),
	}
	serviceInfo := rainslib.ServiceInfo{
		Name:     "lookup",
		Port:     49830,
		Priority: 1,
	}

	nameObject := rainslib.Object{Type: rainslib.OTName, Value: nameObjectContent}
	ip6Object := rainslib.Object{Type: rainslib.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
	ip4Object := rainslib.Object{Type: rainslib.OTIP4Addr, Value: "127.0.0.1"}
	redirObject := rainslib.Object{Type: rainslib.OTRedirection, Value: "ns.ethz.ch"}
	delegObject := rainslib.Object{Type: rainslib.OTDelegation, Value: publicKey}
	nameSetObject := rainslib.Object{Type: rainslib.OTNameset, Value: rainslib.NamesetExpression("Would be an expression")}
	certObject := rainslib.Object{Type: rainslib.OTCertInfo, Value: certificate}
	serviceInfoObject := rainslib.Object{Type: rainslib.OTServiceInfo, Value: serviceInfo}
	registrarObject := rainslib.Object{Type: rainslib.OTRegistrar, Value: "Registrar information"}
	registrantObject := rainslib.Object{Type: rainslib.OTRegistrant, Value: "Registrant information"}
	infraObject := rainslib.Object{Type: rainslib.OTInfraKey, Value: publicKey}
	extraObject := rainslib.Object{Type: rainslib.OTExtraKey, Value: publicKey}
	nextKey := rainslib.Object{Type: rainslib.OTNextKey, Value: publicKeyWithValidity}

	options = []rainslib.Object{nameObject, ip6Object, ip4Object, redirObject, delegObject, nameSetObject, certObject, serviceInfoObject,
		registrarObject, registrantObject, infraObject, extraObject, nextKey}

	//encodings
	encodings := []string{}
	encodings = append(encodings, ":name: ethz2.ch [ ip4 ip6 ]")
	encodings = append(encodings, ":ip6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	encodings = append(encodings, ":ip4: 127.0.0.1")
	encodings = append(encodings, ":redir: ns.ethz.ch")
	encodings = append(encodings, fmt.Sprintf(":deleg: ed25519 %s", hex.EncodeToString(publicKey.Key.(ed25519.PublicKey))))
	encodings = append(encodings, ":nameSet: Would be an expression")
	encodings = append(encodings, fmt.Sprintf(":cert: tls endEntity sha256 %s", hex.EncodeToString(certificate.Data)))
	encodings = append(encodings, ":srv: lookup 49830 1")
	encodings = append(encodings, ":regr: Registrar information")
	encodings = append(encodings, ":regt: Registrant information")
	encodings = append(encodings, fmt.Sprintf(":infra: ed25519 %s", hex.EncodeToString(publicKey.Key.(ed25519.PublicKey))))
	encodings = append(encodings, fmt.Sprintf(":extra: 0 ed25519 %s", hex.EncodeToString(publicKey.Key.(ed25519.PublicKey))))
	encodings = append(encodings, fmt.Sprintf(":next: ed25519 %s 1000 2000", hex.EncodeToString(publicKey.Key.(ed25519.PublicKey))))

	return options, encodings
}

//getSignature returns a signature. Currently it is not used for encoding. It is used to test that encoder can handle unnecessary content on sections
func getSignature() rainslib.Signature {
	return rainslib.Signature{
		KeySpace:   rainslib.RainsKeySpace,
		Algorithm:  rainslib.Ed25519,
		ValidSince: 1000,
		ValidUntil: 2000,
		Data:       []byte("SignatureData")}
}

//getAssertionAndEncodings returns a slice of assertions and a slice of their encodings used for testing
func getAssertionAndEncodings() ([]*rainslib.AssertionSection, []string) {
	//assertions
	assertions := []*rainslib.AssertionSection{}
	objects, objEncodings := getObjectsAndEncodings()

	assertion0 := &rainslib.AssertionSection{
		Content:     objects,
		Context:     "",
		SubjectName: "ethz",
		SubjectZone: "",
		Signatures:  []rainslib.Signature{},
	}
	assertion1 := &rainslib.AssertionSection{
		Content:     objects,
		Context:     ".",
		SubjectName: "ethz",
		SubjectZone: "ch",
		Signatures:  []rainslib.Signature{getSignature()},
	}
	assertions = append(assertions, assertion0)
	assertions = append(assertions, assertion1)

	//encodings
	encodings := []string{}
	encodings = append(encodings, fmt.Sprintf(":A: ethz ch . [ %s ]", strings.Join(objEncodings, " ")))

	return assertions, encodings
}

//getShardAndEncodings returns a slice of shards and a slice of their encodings used for testing
func getShardAndEncodings() ([]*rainslib.ShardSection, []string) {
	//shards
	shards := []*rainslib.ShardSection{}
	assertions, assertionEncodings := getAssertionAndEncodings()

	shard0 := &rainslib.ShardSection{
		Content:     []*rainslib.AssertionSection{assertions[0]},
		Context:     "",
		SubjectZone: "",
		RangeFrom:   "",
		RangeTo:     "",
		Signatures:  []rainslib.Signature{getSignature()},
	}
	shard1 := &rainslib.ShardSection{
		Content:     []*rainslib.AssertionSection{assertions[0]},
		Context:     "",
		SubjectZone: "",
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
		Signatures:  []rainslib.Signature{getSignature()},
	}
	shard2 := &rainslib.ShardSection{
		Content:     []*rainslib.AssertionSection{assertions[0]},
		Context:     ".",
		SubjectZone: "ch",
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
		Signatures:  []rainslib.Signature{getSignature()},
	}
	shard3 := &rainslib.ShardSection{
		Content:     []*rainslib.AssertionSection{assertions[0], assertions[0]},
		Context:     ".",
		SubjectZone: "ethz.ch",
		RangeFrom:   "",
		RangeTo:     "",
		Signatures:  []rainslib.Signature{getSignature()},
	}
	shard4 := &rainslib.ShardSection{
		Context:     ".",
		SubjectZone: "ethz.ch",
		RangeFrom:   "cd",
		RangeTo:     "ef",
		Signatures:  []rainslib.Signature{getSignature()},
	}
	shards = append(shards, shard0)
	shards = append(shards, shard1)
	shards = append(shards, shard2)
	shards = append(shards, shard3)
	shards = append(shards, shard4)

	//encodings
	encodings := []string{}
	encodings = append(encodings, fmt.Sprintf(":S: < > [ %s ]", assertionEncodings[0]))
	encodings = append(encodings, fmt.Sprintf(":S: aaa zzz [ %s ]", assertionEncodings[0]))
	encodings = append(encodings, fmt.Sprintf(":S: ch . aaa zzz [ %s ]", assertionEncodings[0]))
	encodings = append(encodings, fmt.Sprintf(":S: ethz.ch . < > [ %s %s ]", assertionEncodings[0], assertionEncodings[0]))
	encodings = append(encodings, ":S: ethz.ch . cd ef [ ]")

	return shards, encodings
}

//getZonesAndEncodings returns a slice of zones and a slice of their encodings used for testing
func getZonesAndEncodings() ([]*rainslib.ZoneSection, []string) {
	//zones
	zones := []*rainslib.ZoneSection{}
	assertions, assertionEncodings := getAssertionAndEncodings()
	shards, shardEncodings := getShardAndEncodings()

	zone0 := &rainslib.ZoneSection{
		Content:     []rainslib.MessageSectionWithSig{assertions[0], shards[3]},
		Context:     ".",
		SubjectZone: "ch",
		Signatures:  []rainslib.Signature{getSignature()},
	}
	zone1 := &rainslib.ZoneSection{
		Context:     ".",
		SubjectZone: "ch",
		Signatures:  []rainslib.Signature{getSignature()},
	}

	zones = append(zones, zone0)
	zones = append(zones, zone1)

	//encodings
	encodings := []string{}
	encodings = append(encodings, fmt.Sprintf(":Z: ch . [ %s %s ]", assertionEncodings[0], shardEncodings[3]))
	encodings = append(encodings, ":Z: ch . [ ]")

	return zones, encodings
}

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
