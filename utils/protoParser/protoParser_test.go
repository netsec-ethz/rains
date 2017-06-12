package protoParser

import (
	"net"
	"rains/rainslib"
	"testing"
)

func TestEncodeAndDecode(t *testing.T) {
	nameObjectContent := rainslib.NameObject{
		Name:  "ethz2.ch",
		Types: []rainslib.ObjectType{rainslib.OTIP4Addr, rainslib.OTIP6Addr},
	}
	var ed25519Pkey rainslib.Ed25519PublicKey
	copy(ed25519Pkey[:], []byte("01234567890123456789012345678901"))
	publicKey := rainslib.PublicKey{
		KeySpace:   rainslib.RainsKeySpace,
		Type:       rainslib.Ed25519,
		Key:        ed25519Pkey,
		ValidSince: 10000,
		ValidUntil: 50000,
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

	signature := rainslib.Signature{
		KeySpace:   rainslib.RainsKeySpace,
		Algorithm:  rainslib.Ed25519,
		ValidSince: 1000,
		ValidUntil: 2000,
		Data:       []byte("SignatureData")}

	_, subjectAddress1, _ := net.ParseCIDR("127.0.0.1/32")
	_, subjectAddress2, _ := net.ParseCIDR("127.0.0.1/24")

	assertion := &rainslib.AssertionSection{
		Content: []rainslib.Object{nameObject, ip6Object, ip4Object, redirObject, delegObject, nameSetObject, certObject, serviceInfoObject, registrarObject,
			registrantObject, infraObject, extraObject},
		Context:     ".",
		SubjectName: "ethz",
		SubjectZone: "ch",
		Signatures:  []rainslib.Signature{signature},
	}

	shard := &rainslib.ShardSection{
		Content:     []*rainslib.AssertionSection{assertion},
		Context:     ".",
		SubjectZone: "ch",
		RangeFrom:   "aaa",
		RangeTo:     "zzz",
		Signatures:  []rainslib.Signature{signature},
	}

	zone := &rainslib.ZoneSection{
		Content:     []rainslib.MessageSectionWithSig{assertion, shard},
		Context:     ".",
		SubjectZone: "ch",
		Signatures:  []rainslib.Signature{signature},
	}

	query := &rainslib.QuerySection{
		Context: ".",
		Expires: 159159,
		Name:    "ethz.ch",
		Options: []rainslib.QueryOption{rainslib.MinE2ELatency, rainslib.MinInfoLeakage},
		Token:   rainslib.GenerateToken(),
		Type:    rainslib.OTIP4Addr,
	}

	notification := &rainslib.NotificationSection{
		Token: rainslib.GenerateToken(),
		Type:  rainslib.NoAssertionsExist,
		Data:  "Notification information",
	}

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

	addressZone := &rainslib.AddressZoneSection{
		SubjectAddr: subjectAddress2,
		Context:     ".",
		Content:     []*rainslib.AddressAssertionSection{addressAssertion1, addressAssertion2},
		Signatures:  []rainslib.Signature{signature},
	}

	addressQuery := &rainslib.AddressQuerySection{
		SubjectAddr: subjectAddress1,
		Context:     ".",
		Expires:     7564859,
		Token:       rainslib.GenerateToken(),
		Types:       rainslib.OTName,
		Options:     []rainslib.QueryOption{rainslib.MinE2ELatency, rainslib.MinInfoLeakage},
	}

	message := rainslib.RainsMessage{
		Content:      []rainslib.MessageSection{assertion, shard, zone, query, notification, addressAssertion1, addressAssertion2, addressZone, addressQuery},
		Token:        rainslib.GenerateToken(),
		Capabilities: []rainslib.Capability{rainslib.Capability("Test"), rainslib.Capability("Yes!")},
		Signatures:   []rainslib.Signature{signature},
	}

	p := ProtoParserAndFramer{}

	msg, err := p.Encode(message)
	if err != nil {
		t.Error("Failed to encode the message")
	}
	m, err := p.Decode(msg)
	if err != nil {
		t.Error("Failed to decode the message")
	}

	checkMessage(m, message, t)

}

func checkMessage(m1, m2 rainslib.RainsMessage, t *testing.T) {
	if m1.Token != m2.Token {
		t.Error("Token mismatch")
	}
	if len(m1.Capabilities) != len(m2.Capabilities) {
		t.Error("Capabilities mismatch")
	}
	for i := 0; i < len(m1.Capabilities); i++ {
		if m1.Capabilities[i] != m2.Capabilities[i] {
			t.Error("Capabilities mismatch")
		}
	}
	checkSignatures(m1.Signatures, m2.Signatures, t)
	if len(m1.Content) != len(m2.Content) {
		t.Error("Message Content length mismatch")
	}
	for i, s1 := range m1.Content {
		switch s1 := s1.(type) {
		case *rainslib.AssertionSection:
			if s2, ok := m2.Content[i].(*rainslib.AssertionSection); ok {
				checkAssertion(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *rainslib.ShardSection:
			if s2, ok := m2.Content[i].(*rainslib.ShardSection); ok {
				checkShard(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *rainslib.ZoneSection:
			if s2, ok := m2.Content[i].(*rainslib.ZoneSection); ok {
				checkZone(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *rainslib.QuerySection:
			if s2, ok := m2.Content[i].(*rainslib.QuerySection); ok {
				checkQuery(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *rainslib.NotificationSection:
			if s2, ok := m2.Content[i].(*rainslib.NotificationSection); ok {
				checkNotification(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *rainslib.AddressAssertionSection:
			if s2, ok := m2.Content[i].(*rainslib.AddressAssertionSection); ok {
				checkAddressAssertion(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *rainslib.AddressZoneSection:
			if s2, ok := m2.Content[i].(*rainslib.AddressZoneSection); ok {
				checkAddressZone(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *rainslib.AddressQuerySection:
			if s2, ok := m2.Content[i].(*rainslib.AddressQuerySection); ok {
				checkAddressQuery(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		default:
			t.Errorf("Unsupported section type: %T", s1)
		}
	}
}

func checkSignatures(s1, s2 []rainslib.Signature, t *testing.T) {
	if len(s1) != len(s2) {
		t.Error("Signature count mismatch")
	}
	for i := 0; i < len(s1); i++ {
		if s1[i].Algorithm != s2[i].Algorithm {
			t.Errorf("Signature algorithm mismatch in %d. Signature", i)
		}
		if s1[i].KeySpace != s2[i].KeySpace {
			t.Errorf("Signature KeySpace mismatch in %d. Signature", i)
		}
		if s1[i].ValidSince != s2[i].ValidSince {
			t.Errorf("Signature ValidSince mismatch in %d. Signature", i)
		}
		if s1[i].ValidUntil != s2[i].ValidUntil {
			t.Errorf("Signature ValidUntil mismatch in %d. Signature", i)
		}
		switch s1[i].Algorithm {
		case rainslib.Ed25519:
			d1 := s1[i].Data.([]byte)
			d2 := s2[i].Data.([]byte)
			if len(d1) != len(d2) {
				t.Errorf("Signature data length mismatch in %d. Signature", i)
			}
			for j := 0; j < len(d1); j++ {
				if d1[j] != d2[j] {
					t.Errorf("Signature data mismatch at %d. byte in %d. Signature", j, i)
				}
			}
		}
	}
}

func checkAssertion(a1, a2 *rainslib.AssertionSection, t *testing.T) {
	if a1.Context != a2.Context {
		t.Error("Assertion Context mismatch")
	}
	if a1.SubjectZone != a2.SubjectZone {
		t.Error("Assertion SubjectZone mismatch")
	}
	if a1.SubjectName != a2.SubjectName {
		t.Error("Assertion SubjectName mismatch")
	}
	checkSignatures(a1.Signatures, a2.Signatures, t)
	checkObjects(a1.Content, a2.Content, t)
}

func checkShard(s1, s2 *rainslib.ShardSection, t *testing.T) {
	if s1.Context != s2.Context {
		t.Error("Shard context mismatch")
	}
	if s1.SubjectZone != s2.SubjectZone {
		t.Error("Shard subjectZone mismatch")
	}
	if s1.RangeFrom != s2.RangeFrom {
		t.Error("Shard RangeFrom mismatch")
	}
	if s1.RangeTo != s2.RangeTo {
		t.Error("Shard RangeTo mismatch")
	}
	checkSignatures(s1.Signatures, s2.Signatures, t)
	if len(s1.Content) != len(s2.Content) {
		t.Error("Shard Content length mismatch")
	}
	for i, a1 := range s1.Content {
		checkAssertion(a1, s2.Content[i], t)
	}
}

func checkZone(z1, z2 *rainslib.ZoneSection, t *testing.T) {
	if z1.Context != z2.Context {
		t.Error("Zone context mismatch")
	}
	if z1.SubjectZone != z2.SubjectZone {
		t.Error("Zone subjectZone mismatch")
	}
	checkSignatures(z1.Signatures, z2.Signatures, t)
	if len(z1.Content) != len(z2.Content) {
		t.Error("Zone Content length mismatch")
	}
	for i, s1 := range z1.Content {
		switch s1 := s1.(type) {
		case *rainslib.AssertionSection:
			if s2, ok := z2.Content[i].(*rainslib.AssertionSection); ok {
				checkAssertion(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		case *rainslib.ShardSection:
			if s2, ok := z2.Content[i].(*rainslib.ShardSection); ok {
				checkShard(s1, s2, t)
				continue
			}
			t.Errorf("Types at position %d of Content slice are different", i)
		default:
			t.Errorf("Unsupported section type: %T", s1)
		}
	}
}

func checkQuery(q1, q2 *rainslib.QuerySection, t *testing.T) {
	if q1.Context != q2.Context {
		t.Error("Query context mismatch")
	}
	if q1.Expires != q2.Expires {
		t.Error("Query Expires mismatch")
	}
	if q1.Name != q2.Name {
		t.Error("Query Name mismatch")
	}
	if q1.Token != q2.Token {
		t.Error("Query Token mismatch")
	}
	if q1.Type != q2.Type {
		t.Error("Query Type mismatch")
	}
	if len(q1.Options) != len(q2.Options) {
		t.Error("Query Option length mismatch")
	}
	for i, o1 := range q1.Options {
		if o1 != q2.Options[i] {
			t.Errorf("Query Option at position %d mismatch", i)
		}
	}
}

func checkNotification(n1, n2 *rainslib.NotificationSection, t *testing.T) {
	if n1.Type != n2.Type {
		t.Error("Notification Type mismatch")
	}
	if n1.Token != n2.Token {
		t.Error("Notification Token mismatch")
	}
	if n1.Data != n2.Data {
		t.Error("Notification Data mismatch")
	}
}

func checkAddressAssertion(a1, a2 *rainslib.AddressAssertionSection, t *testing.T) {
	if a1.Context != a2.Context {
		t.Error("AddressAssertion Context mismatch")
	}
	checkSignatures(a1.Signatures, a2.Signatures, t)
	checkSubjectAddress(a1.SubjectAddr, a2.SubjectAddr, t)
	checkObjects(a1.Content, a2.Content, t)
}

func checkAddressZone(z1, z2 *rainslib.AddressZoneSection, t *testing.T) {
	if z1.Context != z2.Context {
		t.Error("AddressZone Context mismatch")
	}
	checkSignatures(z1.Signatures, z2.Signatures, t)
	checkSubjectAddress(z1.SubjectAddr, z2.SubjectAddr, t)
	if len(z1.Content) != len(z2.Content) {
		t.Error("AddressZone Content length mismatch")
	}
	for i, a1 := range z1.Content {
		checkAddressAssertion(a1, z2.Content[i], t)
	}
}

func checkAddressQuery(q1, q2 *rainslib.AddressQuerySection, t *testing.T) {
	if q1.Context != q2.Context {
		t.Error("AddressQuery context mismatch")
	}
	if q1.Expires != q2.Expires {
		t.Error("AddressQuery Expires mismatch")
	}
	if q1.Token != q2.Token {
		t.Error("AddressQuery Token mismatch")
	}
	if q1.Types != q2.Types {
		t.Error("AddressQuery Type mismatch")
	}
	if len(q1.Options) != len(q2.Options) {
		t.Error("AddressQuery Option length mismatch")
	}
	for i, o1 := range q1.Options {
		if o1 != q2.Options[i] {
			t.Errorf("AddressQuery Option at position %d mismatch", i)
		}
	}
	checkSubjectAddress(q1.SubjectAddr, q2.SubjectAddr, t)
}

func checkSubjectAddress(a1, a2 *net.IPNet, t *testing.T) {
	if a1.String() != a2.String() {
		t.Error("SubjectAddr mismatch")
	}
}

func checkObjects(objs1, objs2 []rainslib.Object, t *testing.T) {
	if len(objs1) != len(objs2) {
		t.Error("Objects length mismatch")
	}
	for i, o1 := range objs1 {
		o2 := objs2[i]
		if o1.Type != o2.Type {
			t.Errorf("Object Type mismatch at position %d", i)
		}
		switch o1.Type {
		case rainslib.OTName:
			n1 := o1.Value.(rainslib.NameObject)
			n2 := o2.Value.(rainslib.NameObject)
			if n1.Name != n2.Name {
				t.Errorf("Object Value name Name mismatch at position %d", i)
			}
			if len(n1.Types) != len(n2.Types) {
				t.Error("Object Value name types length mismatch")
			}
			for j, t1 := range n1.Types {
				if t1 != n2.Types[j] {
					t.Errorf("Object Value name type mismatch at byte %d of object %d", j, i)
				}
			}
		case rainslib.OTIP6Addr:
			if o1.Value.(string) != o2.Value.(string) {
				t.Errorf("Object Value IP6 mismatch at position %d", i)
			}
		case rainslib.OTIP4Addr:
			if o1.Value.(string) != o2.Value.(string) {
				t.Errorf("Object Value IP4 mismatch at position %d", i)
			}
		case rainslib.OTRedirection:
			if o1.Value.(string) != o2.Value.(string) {
				t.Errorf("Object Value redirection mismatch at position %d", i)
			}
		case rainslib.OTDelegation:
			checkPublicKey(o1.Value.(rainslib.PublicKey), o2.Value.(rainslib.PublicKey), t)
		case rainslib.OTNameset:
			if o1.Value.(rainslib.NamesetExpression) != o2.Value.(rainslib.NamesetExpression) {
				t.Errorf("Object Value nameSet mismatch at position %d", i)
			}
		case rainslib.OTCertInfo:
			c1 := o1.Value.(rainslib.CertificateObject)
			c2 := o2.Value.(rainslib.CertificateObject)
			if c1.Type != c2.Type {
				t.Errorf("Object Value CertificateInfo type mismatch at position %d", i)
			}
			if c1.HashAlgo != c2.HashAlgo {
				t.Errorf("Object Value CertificateInfo HashAlgo mismatch at position %d", i)
			}
			if c1.Usage != c2.Usage {
				t.Errorf("Object Value CertificateInfo Usage mismatch at position %d", i)
			}
			if len(c1.Data) != len(c2.Data) {
				t.Errorf("Object Value CertificateInfo data length mismatch of object %d", i)
			}
			for j, b1 := range c1.Data {
				if b1 != c2.Data[j] {
					t.Errorf("Object Value CertificateInfo data mismatch at byte %d of object %d", j, i)
				}
			}
		case rainslib.OTServiceInfo:
			s1 := o1.Value.(rainslib.ServiceInfo)
			s2 := o2.Value.(rainslib.ServiceInfo)
			if s1.Name != s2.Name {
				t.Errorf("Object Value service info name mismatch at position %d", i)
			}
			if s1.Port != s2.Port {
				t.Errorf("Object Value service info Port mismatch at position %d", i)
			}
			if s1.Priority != s2.Priority {
				t.Errorf("Object Value service info Priority mismatch at position %d", i)
			}
		case rainslib.OTRegistrar:
			if o1.Value.(string) != o2.Value.(string) {
				t.Errorf("Object Value registrar mismatch at position %d", i)
			}
		case rainslib.OTRegistrant:
			if o1.Value.(string) != o2.Value.(string) {
				t.Errorf("Object Value registrant mismatch at position %d", i)
			}
		case rainslib.OTInfraKey:
			checkPublicKey(o1.Value.(rainslib.PublicKey), o2.Value.(rainslib.PublicKey), t)
		case rainslib.OTExtraKey:
			checkPublicKey(o1.Value.(rainslib.PublicKey), o2.Value.(rainslib.PublicKey), t)
		}
	}
}

func checkPublicKey(p1, p2 rainslib.PublicKey, t *testing.T) {
	if p1.KeySpace != p2.KeySpace {
		t.Error("SubjectAddr KeySpace mismatch")
	}
	if p1.Type != p2.Type {
		t.Error("SubjectAddr Type mismatch")
	}
	if p1.ValidSince != p2.ValidSince {
		t.Error("SubjectAddr ValidSince mismatch")
	}
	if p1.ValidUntil != p2.ValidUntil {
		t.Error("SubjectAddr ValidUntil mismatch")
	}
	switch p1 := p1.Key.(type) {
	case rainslib.Ed25519PublicKey:
		if p2, ok := p2.Key.(rainslib.Ed25519PublicKey); ok {
			if p1 != p2 {
				t.Errorf("publickey key mismatch p1=%v != %v=p2", p1, p2)
			}
		} else {
			t.Errorf("publickey key type mismatch. Got Type:%T", p2)
		}
	default:
		t.Errorf("Not yet supported. Got Type:%T", p1)
	}
}
