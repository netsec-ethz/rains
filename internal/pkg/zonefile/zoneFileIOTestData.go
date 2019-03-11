package zonefile

import (
	"encoding/hex"
	"fmt"

	"github.com/netsec-ethz/rains/internal/pkg/algorithmTypes"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"

	"golang.org/x/crypto/ed25519"
)

type objectIndent struct {
	Objects [][]object.Object
	Indents []string
}

//getObjectsAndEncodings returns a slice of options and a slice of their encodings used for testing
func getObjectsAndEncodings() (objectIndent, []string) {
	//objects
	objects := [][]object.Object{}
	nameObjectContent := object.Name{
		Name:  "ethz2.ch",
		Types: []object.Type{object.OTIP4Addr, object.OTIP6Addr},
	}
	pubKey, _, _ := ed25519.GenerateKey(nil)
	publicKey := keys.PublicKey{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			Algorithm: algorithmTypes.Ed25519,
		},
		Key: pubKey,
	}
	publicKeyWithValidity := keys.PublicKey{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			Algorithm: algorithmTypes.Ed25519,
		},
		Key:        pubKey,
		ValidSince: 1000,
		ValidUntil: 20000,
	}
	certificate0 := object.Certificate{
		Type:     object.PTTLS,
		HashAlgo: algorithmTypes.Sha256,
		Usage:    object.CUEndEntity,
		Data:     []byte("certData"),
	}
	certificate1 := object.Certificate{
		Type:     object.PTUnspecified,
		HashAlgo: algorithmTypes.Sha512,
		Usage:    object.CUTrustAnchor,
		Data:     []byte("certData"),
	}
	certificate2 := object.Certificate{
		Type:     object.PTUnspecified,
		HashAlgo: algorithmTypes.Sha384,
		Usage:    object.CUTrustAnchor,
		Data:     []byte("certData"),
	}
	certificate3 := object.Certificate{
		Type:     object.PTUnspecified,
		HashAlgo: algorithmTypes.NoHashAlgo,
		Usage:    object.CUTrustAnchor,
		Data:     []byte("certData"),
	}
	serviceInfo := object.ServiceInfo{
		Name:     "lookup",
		Port:     49830,
		Priority: 1,
	}

	nameObject0 := object.Object{Type: object.OTName, Value: nameObjectContent}
	nameObjectEncoding0 := ":name:      ethz2.ch [ :ip4: :ip6: ]\n"
	ip6Object0 := object.Object{Type: object.OTIP6Addr, Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
	ip6ObjectEncoding0 := ":ip6:       2001:0db8:85a3:0000:0000:8a2e:0370:7334\n"
	ip4Object0 := object.Object{Type: object.OTIP4Addr, Value: "127.0.0.1"}
	ip4ObjectEncoding0 := ":ip4:       127.0.0.1\n"
	redirObject0 := object.Object{Type: object.OTRedirection, Value: "ns.ethz.ch"}
	redirObjectEncoding0 := ":redir:     ns.ethz.ch\n"
	delegObject0 := object.Object{Type: object.OTDelegation, Value: publicKey}
	delegObjectEncoding0 := fmt.Sprintf(":deleg:     :ed25519: 0 %s\n", hex.EncodeToString(publicKey.Key.(ed25519.PublicKey)))
	nameSetObject0 := object.Object{Type: object.OTNameset, Value: object.NamesetExpr("Would be an expression")}
	nameSetObjectEncoding0 := ":nameset:   Would be an expression\n"
	certObject0 := object.Object{Type: object.OTCertInfo, Value: certificate0}
	certObjectEncoding0 := fmt.Sprintf(":cert:      :tls: :endEntity: :sha256: %s\n", hex.EncodeToString(certificate0.Data))
	certObject1 := object.Object{Type: object.OTCertInfo, Value: certificate1}
	certObjectEncoding1 := fmt.Sprintf(":cert:      :unspecified: :trustAnchor: :sha512: %s\n", hex.EncodeToString(certificate1.Data))
	certObject2 := object.Object{Type: object.OTCertInfo, Value: certificate2}
	certObjectEncoding2 := fmt.Sprintf(":cert:      :unspecified: :trustAnchor: :sha384: %s\n", hex.EncodeToString(certificate2.Data))
	certObject3 := object.Object{Type: object.OTCertInfo, Value: certificate3}
	certObjectEncoding3 := fmt.Sprintf(":cert:      :unspecified: :trustAnchor: :noHash: %s\n", hex.EncodeToString(certificate3.Data))
	serviceInfoObject0 := object.Object{Type: object.OTServiceInfo, Value: serviceInfo}
	serviceInfoObjectEncoding0 := ":srv:       lookup 49830 1\n"
	registrarObject0 := object.Object{Type: object.OTRegistrar, Value: "Registrar information"}
	registrarObjectEncoding0 := ":regr:      Registrar information\n"
	registrantObject0 := object.Object{Type: object.OTRegistrant, Value: "Registrant information"}
	registrantObjectEncoding0 := ":regt:      Registrant information\n"
	infraObject0 := object.Object{Type: object.OTInfraKey, Value: publicKey}
	infraObjectEncoding0 := fmt.Sprintf(":infra:     :ed25519: 0 %s\n", hex.EncodeToString(publicKey.Key.(ed25519.PublicKey)))
	extraObject0 := object.Object{Type: object.OTExtraKey, Value: publicKey}
	extraObjectEncoding0 := fmt.Sprintf(":extra:      :ed25519: 0 %s\n", hex.EncodeToString(publicKey.Key.(ed25519.PublicKey)))
	nextObject0 := object.Object{Type: object.OTNextKey, Value: publicKeyWithValidity}
	nextObjectEncoding0 := fmt.Sprintf(":next:      :ed25519: 0 %s 1000 20000\n", hex.EncodeToString(publicKey.Key.(ed25519.PublicKey)))

	objects = append(objects, []object.Object{nameObject0, ip6Object0, ip4Object0, redirObject0, delegObject0, nameSetObject0, certObject0, serviceInfoObject0,
		registrarObject0, registrantObject0, infraObject0, extraObject0, nextObject0})
	objects = append(objects, []object.Object{nameObject0})
	objects = append(objects, []object.Object{ip6Object0})
	objects = append(objects, []object.Object{ip4Object0})
	objects = append(objects, []object.Object{redirObject0})
	objects = append(objects, []object.Object{delegObject0})
	objects = append(objects, []object.Object{nameSetObject0})
	objects = append(objects, []object.Object{certObject0})
	objects = append(objects, []object.Object{serviceInfoObject0})
	objects = append(objects, []object.Object{registrarObject0})
	objects = append(objects, []object.Object{registrantObject0})
	objects = append(objects, []object.Object{infraObject0})
	objects = append(objects, []object.Object{extraObject0})
	objects = append(objects, []object.Object{nextObject0})
	objects = append(objects, []object.Object{certObject1})
	objects = append(objects, []object.Object{certObject2})
	objects = append(objects, []object.Object{certObject3})

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
	encodings = append(encodings, certObjectEncoding1)
	encodings = append(encodings, certObjectEncoding2)
	encodings = append(encodings, certObjectEncoding3)
	//remove the last new line of each encoding
	for i := range encodings {
		encodings[i] = encodings[i][:len(encodings[i])-1]
	}

	indents := []string{}
	indents = append(indents, indent12)
	for i := 0; i < len(encodings)-1; i++ {
		indents = append(indents, "")
	}
	return objectIndent{Objects: objects, Indents: indents}, encodings
}

//getSignature returns a signature. Currently it is not used for encoding. It is used to test that encoder can handle unnecessary content on sections
func getSignature() signature.Sig {
	return signature.Sig{
		PublicKeyID: keys.PublicKeyID{
			KeySpace:  keys.RainsKeySpace,
			Algorithm: algorithmTypes.Ed25519,
		},
		ValidSince: 1000,
		ValidUntil: 2000,
		Data:       []byte("SignatureData")}
}

//getAssertionAndEncodings returns a slice of assertions and a slice of their encodings used for testing
func getAssertionAndEncodings(indent string) ([]*section.Assertion, []string) {
	//assertions
	assertions := []*section.Assertion{}
	objectIndents, objEncodings := getObjectsAndEncodings()

	assertion0 := &section.Assertion{
		Content:     objectIndents.Objects[0],
		Context:     "",
		SubjectName: "ethz",
		SubjectZone: "",
		Signatures:  []signature.Sig{},
	}
	assertion1 := &section.Assertion{
		Content:     objectIndents.Objects[0],
		Context:     ".",
		SubjectName: "ethz",
		SubjectZone: "ch",
		Signatures:  []signature.Sig{getSignature()},
	}
	assertion2 := &section.Assertion{
		Content:     objectIndents.Objects[1],
		Context:     "",
		SubjectName: "ethz",
		SubjectZone: "",
		Signatures:  []signature.Sig{},
	}
	assertion3 := &section.Assertion{
		Content:     objectIndents.Objects[2],
		Context:     "",
		SubjectName: "ethz",
		SubjectZone: "",
		Signatures:  []signature.Sig{},
	}
	assertions = append(assertions, assertion0, assertion1, assertion2, assertion3)

	//encodings
	encodings := []string{}
	encodings = append(encodings, fmt.Sprintf(":A: ethz [ \n%s\n%s] ( \n\n%s)\n", objEncodings[0], indent, indent))
	encodings = append(encodings, fmt.Sprintf(":A: ethz ch . [ \n%s\n%s] ( \n\n%s)\n", objEncodings[0], indent, indent))
	encodings = append(encodings, fmt.Sprintf(":A: ethz [ %s ] ( \n\n%s)\n", objEncodings[1], indent))
	encodings = append(encodings, fmt.Sprintf(":A: ethz [ %s ] ( \n\n%s)\n", objEncodings[2], indent))

	return assertions, encodings
}

//getShardAndEncodings returns a slice of shards and a slice of their encodings used for testing
func getShardAndEncodings() ([]*section.Shard, []string) {
	//shards
	shards := []*section.Shard{}
	assertions, assertionEncodings := getAssertionAndEncodings(indent8)

	shard0 := &section.Shard{
		Content:     []*section.Assertion{assertions[0]},
		Context:     "",
		SubjectZone: "",
		RangeFrom:   "",
		RangeTo:     "",
		Signatures:  []signature.Sig{getSignature()},
	}
	shard1 := &section.Shard{
		Content:     []*section.Assertion{assertions[0]},
		Context:     "",
		SubjectZone: "",
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
		Signatures:  []signature.Sig{getSignature()},
	}
	shard2 := &section.Shard{
		Content:     []*section.Assertion{assertions[0]},
		Context:     ".",
		SubjectZone: "ch",
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
		Signatures:  []signature.Sig{getSignature()},
	}
	shard3 := &section.Shard{
		Content:     []*section.Assertion{assertions[0], assertions[0]},
		Context:     ".",
		SubjectZone: "ethz.ch",
		RangeFrom:   "",
		RangeTo:     "",
		Signatures:  []signature.Sig{getSignature()},
	}
	shard4 := &section.Shard{
		Context:     ".",
		SubjectZone: "ethz.ch",
		RangeFrom:   "cd",
		RangeTo:     "ef",
		Signatures:  []signature.Sig{getSignature()},
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
func getZonesAndEncodings() ([]*section.Zone, []string) {
	//zones
	zones := []*section.Zone{}
	assertions, assertionEncodings := getAssertionAndEncodings(indent4)

	zone0 := &section.Zone{
		Content:     []*section.Assertion{assertions[0]},
		Context:     ".",
		SubjectZone: "ch.",
		Signatures:  []signature.Sig{getSignature()},
	}
	zone1 := &section.Zone{
		Context:     ".",
		SubjectZone: "ch.",
		Signatures:  []signature.Sig{getSignature()},
	}

	zones = append(zones, zone0)
	zones = append(zones, zone1)

	//encodings
	encodings := []string{}
	encodings = append(encodings, fmt.Sprintf(":Z: ch. . [\n%s%s\n]", indent4, assertionEncodings[0])) //when not used for signing, it does not copy context and subjectZone to contained shards and assertions
	encodings = append(encodings, ":Z: ch. . [\n]")

	return zones, encodings
}

//getQueriesAndEncodings returns a slice of queries and a slice of their encodings used for testing
func getQueriesAndEncodings() ([]*query.Name, []string) {
	//addressqueries
	queries := []*query.Name{}
	query := &query.Name{
		Context:    ".",
		Expiration: 159159,
		Name:       "ethz.ch",
		Options:    []query.Option{query.QOMinE2ELatency, query.QOMinInfoLeakage},
		Types:      []object.Type{object.OTIP4Addr},
	}
	queries = append(queries, query)

	//encodings
	encodings := []string{}
	encodings = append(encodings, ":Q: . ethz.ch [ 3 ] 159159 [ 1 3 ]")

	return queries, encodings
}

//getNotificationsAndEncodings returns a slice of notifications and a slice of their encodings used for testing
func getNotificationsAndEncodings() ([]*section.Notification, []string) {
	//addressqueries
	notifications := []*section.Notification{}
	token := token.New()
	encodedToken := hex.EncodeToString(token[:])
	notification := &section.Notification{
		Token: token,
		Type:  section.NTNoAssertionsExist,
		Data:  "Notification information",
	}
	notifications = append(notifications, notification)

	//encodings
	encodings := []string{}
	encodings = append(encodings, fmt.Sprintf(":N: %s 404 Notification information", encodedToken))

	return notifications, encodings
}

//getMessagesAndEncodings returns a slice of messages and a slice of their encodings used for testing
func getMessagesAndEncodings() ([]*message.Message, []string) {
	//messages
	messages := []*message.Message{}
	assertions, assertionencodings := getAssertionAndEncodings(indent4)
	shards, shardencodings := getShardAndEncodings()
	zones, zoneencodings := getZonesAndEncodings()
	queries, queryencodings := getQueriesAndEncodings()
	notifs, notifsencoding := getNotificationsAndEncodings()

	token := token.New()
	capabilities := []message.Capability{message.Capability("capa1"), message.Capability("capa2")}
	encodedToken := hex.EncodeToString(token[:])
	message0 := &message.Message{
		Token:        token,
		Capabilities: capabilities,
		Content:      []section.Section{assertions[0]},
	}
	message1 := &message.Message{
		Token:        token,
		Capabilities: capabilities,
		Content:      []section.Section{shards[0]},
	}
	message2 := &message.Message{
		Token:        token,
		Capabilities: capabilities,
		Content:      []section.Section{zones[1]},
	}
	message3 := &message.Message{
		Token:        token,
		Capabilities: capabilities,
		Content:      []section.Section{queries[0]},
	}
	message4 := &message.Message{
		Token:        token,
		Capabilities: capabilities,
		Content:      []section.Section{},
	}
	message5 := &message.Message{
		Token:        token,
		Capabilities: capabilities,
		Content:      []section.Section{notifs[0]},
	}
	messages = append(messages, message0, message1, message2, message3, message5)
	messages = []*message.Message{}
	messages = append(messages, message3, message4, message5)

	//encodings
	encodings := []string{}
	encodings = append(encodings,
		fmt.Sprintf(":M: [ capa1 capa2 ] %s [\n%s\n]", encodedToken, assertionencodings[0]),
		fmt.Sprintf(":M: [ capa1 capa2 ] %s [\n%s\n]", encodedToken, shardencodings[0]),
		fmt.Sprintf(":M: [ capa1 capa2 ] %s [\n%s\n]", encodedToken, zoneencodings[1]),
		fmt.Sprintf(":M: [ capa1 capa2 ] %s [\n%s\n]", encodedToken, queryencodings[0]),
		fmt.Sprintf(":M: [ capa1 capa2 ] %s [\n%s\n]", encodedToken, notifsencoding[0]),
	)
	encodings = []string{}
	encodings = append(encodings,
		fmt.Sprintf(":M: [ capa1 capa2 ] %s [\n%s\n]", encodedToken, queryencodings[0]),
		fmt.Sprintf(":M: [ capa1 capa2 ] %s [\n%s\n]", encodedToken, ""),
		fmt.Sprintf(":M: [ capa1 capa2 ] %s [\n%s\n]", encodedToken, notifsencoding[0]))

	return messages, encodings
}
