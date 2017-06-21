package zoneFileParser

import (
	"encoding/hex"
	"fmt"
	"net"
	"rains/rainslib"

	"golang.org/x/crypto/ed25519"
)

type ObjectIndent struct {
	Objects [][]rainslib.Object
	Indents []string
}

//getObjectsAndEncodings returns a slice of options and a slice of their encodings used for testing
func getObjectsAndEncodings() (ObjectIndent, []string) {
	//objects
	objects := [][]rainslib.Object{}
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

	nameObject0 := rainslib.Object{Type: rainslib.OTName, Value: nameObjectContent}
	nameObjectEncoding0 := ":name:     ethz2.ch [ ip4 ip6 ]\n"
	ip6Object0 := rainslib.Object{Type: rainslib.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
	ip6ObjectEncoding0 := ":ip6:      2001:0db8:85a3:0000:0000:8a2e:0370:7334\n"
	ip4Object0 := rainslib.Object{Type: rainslib.OTIP4Addr, Value: "127.0.0.1"}
	ip4ObjectEncoding0 := ":ip4:      127.0.0.1\n"
	redirObject0 := rainslib.Object{Type: rainslib.OTRedirection, Value: "ns.ethz.ch"}
	redirObjectEncoding0 := ":redir:    ns.ethz.ch\n"
	delegObject0 := rainslib.Object{Type: rainslib.OTDelegation, Value: publicKey}
	delegObjectEncoding0 := fmt.Sprintf(":deleg:    ed25519 %s\n", hex.EncodeToString(publicKey.Key.(ed25519.PublicKey)))
	nameSetObject0 := rainslib.Object{Type: rainslib.OTNameset, Value: rainslib.NamesetExpression("Would be an expression")}
	nameSetObjectEncoding0 := ":nameset:  Would be an expression\n"
	certObject0 := rainslib.Object{Type: rainslib.OTCertInfo, Value: certificate}
	certObjectEncoding0 := fmt.Sprintf(":cert:     tls endEntity sha256 %s\n", hex.EncodeToString(certificate.Data))
	serviceInfoObject0 := rainslib.Object{Type: rainslib.OTServiceInfo, Value: serviceInfo}
	serviceInfoObjectEncoding0 := ":srv:      lookup 49830 1\n"
	registrarObject0 := rainslib.Object{Type: rainslib.OTRegistrar, Value: "Registrar information"}
	registrarObjectEncoding0 := ":regr:     Registrar information\n"
	registrantObject0 := rainslib.Object{Type: rainslib.OTRegistrant, Value: "Registrant information"}
	registrantObjectEncoding0 := ":regt:     Registrant information\n"
	infraObject0 := rainslib.Object{Type: rainslib.OTInfraKey, Value: publicKey}
	infraObjectEncoding0 := fmt.Sprintf(":infra:    ed25519 %s\n", hex.EncodeToString(publicKey.Key.(ed25519.PublicKey)))
	extraObject0 := rainslib.Object{Type: rainslib.OTExtraKey, Value: publicKey}
	extraObjectEncoding0 := fmt.Sprintf(":extra:    rains ed25519 %s\n", hex.EncodeToString(publicKey.Key.(ed25519.PublicKey)))
	nextObject0 := rainslib.Object{Type: rainslib.OTNextKey, Value: publicKeyWithValidity}
	nextObjectEncoding0 := fmt.Sprintf(":next:     ed25519 %s 1000 20000\n", hex.EncodeToString(publicKey.Key.(ed25519.PublicKey)))

	objects = append(objects, []rainslib.Object{nameObject0, ip6Object0, ip4Object0, redirObject0, delegObject0, nameSetObject0, certObject0, serviceInfoObject0,
		registrarObject0, registrantObject0, infraObject0, extraObject0, nextObject0})
	objects = append(objects, []rainslib.Object{nameObject0})
	objects = append(objects, []rainslib.Object{ip6Object0})
	objects = append(objects, []rainslib.Object{ip4Object0})
	objects = append(objects, []rainslib.Object{redirObject0})
	objects = append(objects, []rainslib.Object{delegObject0})
	objects = append(objects, []rainslib.Object{nameSetObject0})
	objects = append(objects, []rainslib.Object{certObject0})
	objects = append(objects, []rainslib.Object{serviceInfoObject0})
	objects = append(objects, []rainslib.Object{registrarObject0})
	objects = append(objects, []rainslib.Object{registrantObject0})
	objects = append(objects, []rainslib.Object{infraObject0})
	objects = append(objects, []rainslib.Object{extraObject0})
	objects = append(objects, []rainslib.Object{nextObject0})

	//encodings
	encodings := []string{}
	encodings = append(encodings, fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", indent12, nameObjectEncoding0, indent12, ip6ObjectEncoding0,
		indent12, ip4ObjectEncoding0, indent12, redirObjectEncoding0, indent12, delegObjectEncoding0, indent12, nameSetObjectEncoding0, indent12,
		certObjectEncoding0, indent12, serviceInfoObjectEncoding0, indent12, registrarObjectEncoding0, indent12, registrantObjectEncoding0, indent12,
		infraObjectEncoding0, indent12, extraObjectEncoding0, indent12, nextObjectEncoding0))
	encodings = append(encodings, nameObjectEncoding0)
	encodings = append(encodings, ip6ObjectEncoding0)
	encodings = append(encodings, ip4ObjectEncoding0)
	encodings = append(encodings, redirObjectEncoding0)
	encodings = append(encodings, delegObjectEncoding0)
	encodings = append(encodings, nameSetObjectEncoding0)
	encodings = append(encodings, certObjectEncoding0)
	encodings = append(encodings, serviceInfoObjectEncoding0)
	encodings = append(encodings, registrarObjectEncoding0)
	encodings = append(encodings, registrantObjectEncoding0)
	encodings = append(encodings, infraObjectEncoding0)
	encodings = append(encodings, extraObjectEncoding0)
	encodings = append(encodings, nextObjectEncoding0)
	//remove the last new line of each encoding
	for i := range encodings {
		encodings[i] = encodings[i][:len(encodings[i])-1]
	}

	indents := []string{}
	indents = append(indents, indent12)
	for i := 0; i < 13; i++ {
		indents = append(indents, "")
	}
	return ObjectIndent{Objects: objects, Indents: indents}, encodings
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
func getAssertionAndEncodings(indent string) ([]*rainslib.AssertionSection, []string) {
	//assertions
	assertions := []*rainslib.AssertionSection{}
	objectIndents, objEncodings := getObjectsAndEncodings()

	assertion0 := &rainslib.AssertionSection{
		Content:     objectIndents.Objects[0],
		Context:     "",
		SubjectName: "ethz",
		SubjectZone: "",
		Signatures:  []rainslib.Signature{},
	}
	assertion1 := &rainslib.AssertionSection{
		Content:     objectIndents.Objects[0],
		Context:     ".",
		SubjectName: "ethz",
		SubjectZone: "ch",
		Signatures:  []rainslib.Signature{getSignature()},
	}
	assertion2 := &rainslib.AssertionSection{
		Content:     objectIndents.Objects[1],
		Context:     "",
		SubjectName: "ethz",
		SubjectZone: "",
		Signatures:  []rainslib.Signature{},
	}
	assertions = append(assertions, assertion0)
	assertions = append(assertions, assertion1)
	assertions = append(assertions, assertion2)

	//encodings
	encodings := []string{}
	encodings = append(encodings, fmt.Sprintf(":A: ethz   [ \n%s\n%s]", objEncodings[0], indent))
	encodings = append(encodings, fmt.Sprintf(":A: ethz ch . [ \n%s\n%s]", objEncodings[0], indent))
	encodings = append(encodings, fmt.Sprintf(":A: ethz   [ %s ]", objEncodings[1]))

	return assertions, encodings
}

//getShardAndEncodings returns a slice of shards and a slice of their encodings used for testing
func getShardAndEncodings() ([]*rainslib.ShardSection, []string) {
	//shards
	shards := []*rainslib.ShardSection{}
	assertions, assertionEncodings := getAssertionAndEncodings(indent8)

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
	encodings = append(encodings, fmt.Sprintf(":S:   < > [\n%s%s\n%s]", indent8, assertionEncodings[0], indent4))
	encodings = append(encodings, fmt.Sprintf(":S:   aaa zzz [\n%s%s\n%s]", indent8, assertionEncodings[0], indent4))
	encodings = append(encodings, fmt.Sprintf(":S: ch . aaa zzz [\n%s%s\n%s]", indent8, assertionEncodings[0], indent4))
	encodings = append(encodings, fmt.Sprintf(":S: ethz.ch . < > [\n%s%s\n%s%s\n%s]", indent8, assertionEncodings[0], indent8, assertionEncodings[0], indent4))
	encodings = append(encodings, ":S: ethz.ch . cd ef [\n    ]")

	return shards, encodings
}

//getZonesAndEncodings returns a slice of zones and a slice of their encodings used for testing
func getZonesAndEncodings() ([]*rainslib.ZoneSection, []string) {
	//zones
	zones := []*rainslib.ZoneSection{}
	assertions, assertionEncodings := getAssertionAndEncodings(indent4)
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
