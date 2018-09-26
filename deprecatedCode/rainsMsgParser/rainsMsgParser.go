package rainsMsgParser

/*import (
	"encoding/hex"
	"errors"
	"fmt"
	"rains/rainslib"
	"strconv"
	"strings"

	"golang.org/x/crypto/ed25519"

	log "github.com/inconshreveable/log15"
)

//TODO CFE replace this type with the public key type of the crypto library we use for ed448
type Ed448PublicKey [57]byte

//RainsMsgParser contains methods to convert rainsMessages as a byte slice to an internal representation and vice versa
type RainsMsgParser struct{}

//ParseByteSlice parses the byte slice to a RainsMessage according to the following format:
//It is ASSUMED that signature data does not contain the '[' char.
//RainsMessage format: <token>[MessageSection:::::...:::::MessageSection][signatures*]:cap:<capabilities>
//Signed Assertion: :SA::CN:<context-name>:ZN:<zone-name>:SN:<subject-name>[(:OT:<object type>:OD:<object data>)*][signature*]
//Contained Assertion: :CA::SN:<subject-name>[:OT:<object type>:OD:<object data>][signature*]
//Signed Shard: :SS::CN:<context-name>:ZN:<zone-name>:RB:<range-begin>:RE:<range-end>[Contained Assertion*][signature*]
//Contained Shard: :CS::RB:<range-begin>:RE:<range-end>[Contained Assertion*][signature*]
//Zone: :SZ::CN:<context-name>:ZN:<zone-name>[(Contained Shard|Contained Assertion):::...:::(Contained Shard|Contained Assertion)][signature*]
//Query: :QU::VU:<valid-until>:CN:<context-name>:SN:<subject-name>:OT:<objtype>[<option1>:...:<option_n>]
//Notification: :NO::TN:<token this notification refers to>:NT:<type>:ND:<data>
//signature: :VF:<valid-from>:VU:<valid-until>:KS:<key-space>:KA:<key-algorithm>:SD:<signature-data>
func (p RainsMsgParser) ParseByteSlice(message []byte) (message.RainsMessage, error) {
	msg := string(message)
	log.Debug("Parse Rains Message", "message", msg)
	msgSectionBegin := strings.Index(msg, "[")
	msgSectionEnd := strings.LastIndex(msg, "[") - 1
	sigBegin := strings.LastIndex(msg, "[")
	sigEnd := strings.LastIndex(msg, "]")
	capability := strings.Index(msg, ":cap:")
	token, err := p.Token(message)
	if err != nil {
		return message.RainsMessage{}, err
	}
	if msgSectionEnd == -2 || sigBegin == -1 || sigEnd == -1 || capability == -1 {
		log.Warn("Rains Message malformed", "msgSectionEnd", msgSectionEnd, "sigBegin", sigBegin, "sigEnd", sigEnd, "capability", capability)
		return message.RainsMessage{Token: token}, errors.New("Rains Message malformed")
	}
	msgBodies, err := parseMessageBodies(msg[msgSectionBegin+1:msgSectionEnd], token)
	if err != nil {
		return message.RainsMessage{Token: token}, err
	}
	signatures, err := parseSignatures(msg[sigBegin+1 : sigEnd])
	if err != nil {
		return message.RainsMessage{Token: token}, err
	}
	capabilities := msg[capability+5:]
	parsedCapabilities := []message.Capability{}
	if capabilities != "" {
		log.Warn("TODO CFE capability parsing not yet implemented")
	}
	log.Debug("Successfully finished parsing rains message")
	return message.RainsMessage{Token: token, Content: msgBodies, Signatures: signatures, Capabilities: parsedCapabilities}, nil
}

//ParseRainsMsg parses a RainsMessage to a byte slice representation with format:
//<token>[MessageSection:::::...:::::MessageSection][signatures*]:cap:<capabilities>
func (p RainsMsgParser) ParseRainsMsg(m message.RainsMessage) ([]byte, error) {

	msg := hex.EncodeToString(m.Token[:]) + "["
	for _, section := range m.Content {
		switch section := section.(type) {
		case *sections.AssertionSection:
			msg += revParseSignedAssertion(section)
		case *sections.ShardSection:
			msg += revParseSignedShard(section)
		case *sections.ZoneSection:
			msg += revParseSignedZone(section)
		case *sections.QuerySection:
			msg += revParseQuery(section)
		case *sections.NotificationSection:
			msg += revParseNotification(section)
		default:
			log.Warn("Unknown message section type", "type", fmt.Sprintf("%T", section), "section", section)
			return []byte{}, errors.New("Unknown message section type")
		}
	}
	caps := ""
	if len(m.Capabilities) > 0 {
		caps = string(m.Capabilities[0])
		for _, capa := range m.Capabilities[1:] {
			caps += ":::" + string(capa)
		}
	}
	return []byte(fmt.Sprintf("%s][%s]:cap:%s", msg, revParseSignature(m.Signatures), caps)), nil
}

//Token returns the Token from the message represented as a byte slice with format:
//<token>[MessageSection:::::...:::::MessageSection][signatures*]:cap:<capabilities
func (p RainsMsgParser) Token(message []byte) (token.Token, error) {
	msg := string(message)
	msgSectionBegin := strings.Index(msg, "[")
	if msgSectionBegin == -1 {
		log.Warn("Rains Message malformed, cannot extract token")
		return token.Token{}, errors.New("Rains Message malformed, cannot extract token")
	}
	if hex.DecodedLen(len(message[:msgSectionBegin])) == 16 {
		token := [16]byte{}
		hex.Decode(token[:], message[:msgSectionBegin])
		return token.Token(token), nil
	}
	log.Error("Token is larger than 16 byte", "tokenSize", msgSectionBegin)
	return token.Token{}, errors.New("Token is larger than 16 byte")
}

//RevParseSignedMsgSection parses an MessageSectionWithSig to a byte slice representation
func (p RainsMsgParser) RevParseSignedMsgSection(section sections.MessageSectionWithSig) (string, error) {
	switch section := section.(type) {
	case *sections.AssertionSection:
		return revParseSignedAssertion(section), nil
	case *sections.ShardSection:
		return revParseSignedShard(section), nil
	case *sections.ZoneSection:
		return revParseSignedZone(section), nil
	case *sections.AddressAssertionSection:
		return revParseAddressAssertion(section), nil
	case *sections.AddressZoneSection:
		return revParseAddressZone(section), nil
	default:
		log.Warn("Unknown message section section type", "type", section)
		return "", errors.New("Unknown message section section type")
	}
}

//ParseSignedAssertion parses a byte slice representation of an assertion to the internal representation of an assertion.
//:SA::CN:<context-name>:ZN:<zone-name>:SN:<subject-name>[:OT:<object type>:OD:<object data>][signature*]
func (p RainsMsgParser) ParseSignedAssertion(assertion []byte) (*sections.AssertionSection, error) {
	return parseSignedAssertion(string(assertion))
}

//RevParseSignedAssertion parses a signed assertion to its string representation with format:
//:SA::CN:<context-name>:ZN:<zone-name>:SN:<subject-name>[:OT:<object type>:OD:<object data>][signature*]
func revParseSignedAssertion(a *sections.AssertionSection) string {
	assertion := fmt.Sprintf(":SA::CN:%s:ZN:%s:SN:%s[%s]][", a.Context, a.SubjectZone, a.SubjectName, revParseObjects(a.Content))
	return fmt.Sprintf("%s][%s]", assertion, revParseSignature(a.Signatures))
}

//revParseContainedAssertion parses a contained assertion to its string representation with format:
//:CA::SN:<subject-name>[:OT:<object type>:OD:<object data>][signature*]
func revParseContainedAssertion(a *sections.AssertionSection) string {
	assertion := fmt.Sprintf(":CA::SN:%s[%s]][", a.SubjectName, revParseObjects(a.Content))
	return fmt.Sprintf("%s][%s]", assertion, revParseSignature(a.Signatures))
}

//revParseObjects parses objects to their string representation with format:
//(:OT:<object type>:OD:<object data>)*
func revParseObjects(content []object.Object) string {
	objs := ""
	for _, obj := range content {
		switch value := obj.Value.(type) {
		//FIXME CFE make sure that all delegation, cert, infra and external type are correctly encoded.
		case keys.PublicKey:
			switch key := value.Key.(type) {
			case ed25519.PublicKey:
				objs += fmt.Sprintf(":OT:%v:OD:%d:KD:%v", obj.Type, keys.Ed25519, hex.EncodeToString(key))
			case Ed448PublicKey:
				objs += fmt.Sprintf(":OT:%v:OD:%d:KD:%v", obj.Type, keys.Ed448, hex.EncodeToString(key[:]))
			default:
				log.Warn("not yet implemented public key type", "type", fmt.Sprintf("%T", key), "obj", obj)
				objs += fmt.Sprintf(":OT:%v:OD:%v", obj.Type, obj.Value)
			}
		default:
			objs += fmt.Sprintf(":OT:%v:OD:%v", obj.Type, obj.Value)
		}
	}
	return objs
}

//RevParseSignedShard parses a signed shard to its string representation with format:
//:SS::CN:<context-name>:ZN:<zone-name>:RB:<range-begin>:RE:<range-end>[Contained Assertion*][signature*]
func revParseSignedShard(s *sections.ShardSection) string {
	shard := fmt.Sprintf(":SS::CN:%s:ZN:%s:RB:%s:RE:%s[", s.Context, s.SubjectZone, s.RangeFrom, s.RangeTo)
	for _, assertion := range s.Content {
		shard += revParseContainedAssertion(assertion)
	}
	return fmt.Sprintf("%s][%s]", shard, revParseSignature(s.Signatures))
}

//revParseContainedShard parses a signed shard to its string representation with format:
//:CS::RB:<range-begin>:RE:<range-end>[Contained Assertion*][signature*]
func revParseContainedShard(s *sections.ShardSection) string {
	shard := fmt.Sprintf(":CS::RB:%s:RE:%s[", s.RangeFrom, s.RangeTo)
	for _, assertion := range s.Content {
		shard += revParseContainedAssertion(assertion)
	}
	return fmt.Sprintf("%s][%s]", shard, revParseSignature(s.Signatures))
}

//RevParseSignedShard parses a signed zone to its string representation with format:
//:SZ::CN:<context-name>:ZN:<zone-name>[(Contained Shard|Contained Assertion):::...:::(Contained Shard|Contained Assertion)][signature*]
func revParseSignedZone(z *sections.ZoneSection) string {
	zone := fmt.Sprintf(":SZ::CN:%s:ZN:%s[", z.Context, z.SubjectZone)
	for _, section := range z.Content {
		switch section := section.(type) {
		case *sections.AssertionSection:
			zone += revParseContainedAssertion(section) + ":::"
		case *sections.ShardSection:
			zone += revParseContainedShard(section) + ":::"
		default:
			log.Warn("Unsupported message section type", "msgSection", section)
		}
	}
	if len(z.Content) > 0 {
		zone = zone[:len(zone)-3]
	}
	return fmt.Sprintf("%s][%s]", zone, revParseSignature(z.Signatures))
}

//revParseSignature parses a rains signature to its string representation with format:
//signature: :VF:<valid-from>:VU:<valid-until>:KS:<key-space>:KA:<key-algorithm>:SD:<signature-data>
func revParseSignature(sigs []signature.Signature) string {
	signatures := ""
	for _, sig := range sigs {
		//FIXME CFE support all signature data connection for encoding
		sigDataEnc := sig.Data
		switch sigData := sig.Data.(type) {
		case []byte:
			sigDataEnc = hex.EncodeToString(sigData)
		default:
			log.Warn("Signature data type not yet supported")
		}
		signatures += fmt.Sprintf(":VF:%d:VU:%d:KS:%d:KA:%v:SD:%s", sig.ValidSince, sig.ValidUntil, sig.KeySpace, sig.Algorithm, sigDataEnc)
	}
	return signatures
}

//revParseQuery parses a rains query to its string representation with format:
//:QU::VU:<valid-until>:CN:<context-name>:SN:<subject-name>:OT:<objtype>[<option1>:...:<option_n>]
func revParseQuery(q *sections.QuerySection) string {
	opts := ""
	for _, option := range q.Options {
		opts += fmt.Sprintf("%d:", option)
	}
	if len(q.Options) > 0 {
		opts = opts[:len(opts)-1]
	}
	return fmt.Sprintf(":QU::VU:%d:CN:%s:SN:%s:OT:%d[%s]", q.Expires, q.Context, q.Name, q.Type, opts)
}

//revParseAddressAssertion parses a address assertion to its string representation with format:
//:AA::CN:<context-name>:AF:<address-family>:PL:<prefix-length>:IP:<IP-Address>[(Object)*][]
func revParseAddressAssertion(a *sections.AddressAssertionSection) string {
	prefixLength, _ := a.SubjectAddr.Mask.Size()
	addressFamily := object.OTIP6Addr
	if a.SubjectAddr.IP.To4() != nil {
		addressFamily = object.OTIP4Addr
	}
	assertion := fmt.Sprintf(":AA::CN:%s:AF:%d:PL:%d:IP:%s[%s]][",
		a.Context,
		addressFamily,
		prefixLength,
		a.SubjectAddr.IP,
		revParseObjects(a.Content))
	return fmt.Sprintf("%s][]", assertion)
}

//revParseAddressZone parses a address zone to its string representation with format:
//:AZ::CN:<context-name>:AF:<address-family>:PL:<prefix-length>:IP:<IP-Address>[(Address Assertion)*][]
func revParseAddressZone(z *sections.AddressZoneSection) string {
	prefixLength, _ := z.SubjectAddr.Mask.Size()
	addressFamily := object.OTIP6Addr
	if z.SubjectAddr.IP.To4() != nil {
		addressFamily = object.OTIP4Addr
	}
	zone := fmt.Sprintf(":AZ::CN:%s:AF:%d:PL:%d:IP:%s[",
		z.Context,
		addressFamily,
		prefixLength,
		z.SubjectAddr.IP)
	for _, assertion := range z.Content {
		zone += revParseAddressAssertion(assertion)
	}
	return fmt.Sprintf("%s][]", zone)
}

//revParseNotification parses a rains notification to its string representation with format:
//:NO::TN:<token this notification refers to>:NT:<type>:ND:<data>
func revParseNotification(n *sections.NotificationSection) string {

	return fmt.Sprintf(":NO::TN:%s:NT:%v:ND:%s", hex.EncodeToString(n.Token[:]), n.Type, n.Data)
}

//parseMessageBodies parses message section bodies according to their type (assertion, query, notification)
func parseMessageBodies(msg string, token token.Token) ([]sections.MessageSection, error) {
	log.Debug("Parse Message Bodies", "msgBodies", msg)
	parsedMsgBodies := []sections.MessageSection{}
	if len(msg) == 0 {
		return parsedMsgBodies, nil
	}
	msgBodies := strings.Split(msg, ":::::")
	for _, msgSection := range msgBodies {
		switch t := msgSection[0:4]; t {
		case ":SA:":
			assertionSection, err := parseSignedAssertion(msgSection)
			if err != nil {
				return []sections.MessageSection{}, err
			}
			parsedMsgBodies = append(parsedMsgBodies, assertionSection)
		case ":SS:":
			shardSection, err := parseSignedShard(msgSection)
			if err != nil {
				return []sections.MessageSection{}, err
			}
			parsedMsgBodies = append(parsedMsgBodies, shardSection)
		case ":SZ:":
			zoneSection, err := parseSignedZone(msgSection)
			if err != nil {
				return []sections.MessageSection{}, err
			}
			parsedMsgBodies = append(parsedMsgBodies, zoneSection)
		case ":QU:":
			querySection, err := parseQuery(msgSection, token)
			if err != nil {
				return []sections.MessageSection{}, err
			}
			parsedMsgBodies = append(parsedMsgBodies, querySection)
		case ":NO:":
			notificationSection, err := parseNotification(msgSection)
			if err != nil {
				return []sections.MessageSection{}, err
			}
			parsedMsgBodies = append(parsedMsgBodies, notificationSection)
		default:
			log.Warn("Unknown or Unsupported message type", "type", t)
			return []sections.MessageSection{}, errors.New("Unknown or Unsupported message type")
		}
	}
	return parsedMsgBodies, nil
}

//parseSignedAssertion parses a signed assertion message section with format:
//:SA::CN:<context-name>:ZN:<zone-name>:SN:<subject-name>[:OT:<object type>:OD:<object data>][signature*]
func parseSignedAssertion(msg string) (*sections.AssertionSection, error) {
	log.Debug("Parse Signed Assertion", "assertion", msg)
	cn := strings.Index(msg, ":CN:")
	zn := strings.Index(msg, ":ZN:")
	sn := strings.Index(msg, ":SN:")
	objBegin := strings.Index(msg, "[")
	objEnd := strings.LastIndex(msg, "[") - 2
	sigBegin := strings.LastIndex(msg, "[")
	sigEnd := strings.LastIndex(msg, "]")
	if cn == -1 || zn == -1 || sn == -1 || objBegin == -1 || objEnd == -1 || sigBegin == -1 || sigEnd == -1 {
		log.Warn("Assertion Msg Section malformed")
		return &sections.AssertionSection{}, errors.New("Assertion Msg Section malformed")
	}
	objects, err := parseObjects(msg[objBegin+1 : objEnd])
	if err != nil {
		return &sections.AssertionSection{}, err
	}
	signatures, err := parseSignatures(msg[sigBegin+1 : sigEnd])
	if err != nil {
		return &sections.AssertionSection{}, err
	}
	assertionSection := sections.AssertionSection{Context: msg[cn+4 : zn], SubjectZone: msg[zn+4 : sn], SubjectName: msg[sn+4 : objBegin], Content: objects, Signatures: signatures}
	log.Debug("Successfully finished parsing signed assertion")
	return &assertionSection, nil
}

//parseContainedAssertion parses a contained assertion message section with format:
//:CA::SN:<subject-name>:OT:<object type>:OD:<object data>[signature*]
func parseContainedAssertion(msg, context, subjectZone string) (*sections.AssertionSection, error) {
	log.Debug("Parse Contained Assertion", "assertion", msg)
	sn := strings.Index(msg, ":SN:")
	objBegin := strings.Index(msg, "[")
	objEnd := strings.LastIndex(msg, "[") - 2
	sigBegin := strings.LastIndex(msg, "[")
	sigEnd := strings.LastIndex(msg, "]")
	if sn == -1 || objBegin == -1 || objEnd == -1 || sigBegin == -1 || sigEnd == -1 {
		log.Warn("Assertion Msg Section malformed")
		return &sections.AssertionSection{}, errors.New("Assertion Msg Section malformed")
	}
	objects, err := parseObjects(msg[objBegin+1 : objEnd])
	if err != nil {
		return &sections.AssertionSection{}, err
	}
	if err != nil {
		log.Warn("objType malformed")
		return &sections.AssertionSection{}, errors.New("objType malformed")
	}
	signatures, err := parseSignatures(msg[sigBegin+1 : sigEnd])
	if err != nil {
		return &sections.AssertionSection{}, err
	}
	assertionSection := sections.AssertionSection{
		Context:     context,
		SubjectZone: subjectZone,
		SubjectName: msg[sn+4 : objBegin],
		Content:     objects,
		Signatures:  signatures,
	}
	log.Debug("Successfully finished parsing contained assertion")
	return &assertionSection, nil
}

//parseObjects parses objects with format:
//(:OT:<object type>:OD:<object data>)*
func parseObjects(inputObjects string) ([]object.Object, error) {
	log.Debug("Parse Objects", "objects", inputObjects)
	objects := []object.Object{}
	if len(inputObjects) == 0 {
		return objects, nil
	}
	objs := strings.Split(inputObjects, ":OT:")[1:]
	for _, obj := range objs {
		od := strings.Split(obj, ":OD:")
		if len(od) != 2 {
			log.Warn("object malformed", "object", obj)
			return []object.Object{}, errors.New("object malformed")
		}
		objectType, err := strconv.Atoi(od[0])
		if err != nil {
			log.Warn("Object's objectType malformed")
			return []object.Object{}, errors.New("Object's objectType malformed")
		}
		if objectType == int(object.OTDelegation) {
			pkData := strings.Split(od[1], ":KD:")
			pkType, err := strconv.Atoi(pkData[0])
			if err != nil {
				log.Warn("Was not able to parse the public key type", "type", pkData[0], "error", err)
			}
			switch algorithmTypes.SignatureAlgorithmType(pkType) {
			case keys.Ed25519:
				keyData, err := hex.DecodeString(pkData[1])
				if err != nil || len(keyData) != 32 {
					log.Warn("Object's value malformed.", "bytestring", od[1], "error", err)
					return []object.Object{}, errors.New("Object's objectValue malformed, could not decode")
				}
				publicKey := keys.PublicKey{Key: ed25519.PublicKey(keyData), Type: keys.Ed25519}
				object := object.Object{Type: object.ObjectType(objectType), Value: publicKey}
				objects = append(objects, object)
			case keys.Ed448:
				log.Warn("TODO CFE not yet implemented")
			default:
				log.Warn("TODO CFE not yet implemented")
				continue
			}

		} else {
			object := object.Object{Type: object.ObjectType(objectType), Value: od[1]}
			objects = append(objects, object)
		}

	}
	log.Debug("Successfully finished parsing objects")
	return objects, nil
}

//parseSignedShard parses a signed shard message section with format:
//:SS::CN:<context-name>:ZN:<zone-name>:RB:<range-begin>:RE:<range-end>[ContainedAssertion*][signature*]
func parseSignedShard(msg string) (*sections.ShardSection, error) {
	log.Debug("Parse Signed Shard", "Shard", msg)
	cn := strings.Index(msg, ":CN:")
	zn := strings.Index(msg, ":ZN:")
	rb := strings.Index(msg, ":RB:")
	re := strings.Index(msg, ":RE:")
	assertBegin := strings.Index(msg, "[")
	assertEnd := strings.LastIndex(msg, "[") - 1
	sigBegin := strings.LastIndex(msg, "[")
	sigEnd := strings.LastIndex(msg, "]")
	if zn == -1 || cn == -1 || rb == -1 || re == -1 || assertBegin == -1 || assertEnd == -2 || sigBegin == -1 || sigEnd == -1 {
		log.Warn("Shard Msg Section malformed")
		return &sections.ShardSection{}, errors.New("Shard Msg Section malformed")
	}
	assertions := strings.Split(msg[assertBegin+1:assertEnd], ":CA:")[1:]
	assertionBodies := []*sections.AssertionSection{}
	for _, assertion := range assertions {
		assertionSection, err := parseContainedAssertion(assertion, msg[cn+4:zn], msg[zn+4:rb])
		if err != nil {
			return &sections.ShardSection{}, err
		}
		assertionSection.Context = msg[cn+4 : zn]
		assertionSection.SubjectZone = msg[zn+4 : rb]
		assertionBodies = append(assertionBodies, assertionSection)
	}
	signatures, err := parseSignatures(msg[sigBegin+1 : sigEnd])
	if err != nil {
		return &sections.ShardSection{}, err
	}
	shardSection := sections.ShardSection{
		Context:     msg[cn+4 : zn],
		SubjectZone: msg[zn+4 : rb],
		RangeFrom:   msg[rb+4 : re],
		RangeTo:     msg[re+4 : assertBegin],
		Content:     assertionBodies,
		Signatures:  signatures,
	}
	log.Debug("Successfully finished parsing signed shard")
	return &shardSection, nil
}

//parseContainedShard parses a contained shard message section with format:
//:CS::RB:<range-begin>:RE:<range-end>[ContainedAssertion*][signature*]
func parseContainedShard(msg, context, subjectZone string) (*sections.ShardSection, error) {
	log.Debug("Parse Contained Shard", "shard", msg)
	rb := strings.Index(msg, ":RB:")
	re := strings.Index(msg, ":RE:")
	assertBegin := strings.Index(msg, "[")
	assertEnd := strings.LastIndex(msg, "[") - 1
	sigBegin := strings.LastIndex(msg, "[")
	sigEnd := strings.LastIndex(msg, "]")
	if rb == -1 || re == -1 || assertBegin == -1 || assertEnd == -2 || sigBegin == -1 || sigEnd == -1 {
		log.Warn("Shard Msg Section malformed")
		return &sections.ShardSection{}, errors.New("Shard Msg Section malformed")
	}
	assertions := strings.Split(msg[assertBegin+1:assertEnd], ":CA:")[1:]
	assertionBodies := []*sections.AssertionSection{}
	for _, assertion := range assertions {
		assertionSection, err := parseContainedAssertion(assertion, context, subjectZone)
		if err != nil {
			return &sections.ShardSection{}, err
		}
		assertionBodies = append(assertionBodies, assertionSection)
	}
	signatures, err := parseSignatures(msg[sigBegin+1 : sigEnd])
	if err != nil {
		return &sections.ShardSection{}, err
	}
	shardSection := sections.ShardSection{
		Context:     context,
		SubjectZone: subjectZone,
		RangeFrom:   msg[rb+4 : re],
		RangeTo:     msg[re+4 : assertBegin],
		Content:     assertionBodies,
		Signatures:  signatures,
	}
	log.Debug("Successfully finished parsing contained shard")
	return &shardSection, nil
}

//parseSignedZone parses a signed zone message section with format:
//:SZ::CN:<context-name>:ZN:<zone-name>[(Contained Shard|Contained Assertion):::...:::(Contained Shard|Contained Assertion)][signature*]
func parseSignedZone(msg string) (*sections.ZoneSection, error) {
	log.Debug("Parse Signed Zone", "zone", msg)
	cn := strings.Index(msg, ":CN:")
	zn := strings.Index(msg, ":ZN:")
	sectionBegin := strings.Index(msg, "[")
	sectionEnd := strings.LastIndex(msg, "[") - 1
	sigBegin := strings.LastIndex(msg, "[")
	sigEnd := strings.LastIndex(msg, "]")
	if zn == -1 || cn == -1 || sectionBegin == -1 || sectionEnd == -2 || sigBegin == -1 || sigEnd == -1 {
		log.Warn("Shard Msg Section malformed")
		return &sections.ZoneSection{}, errors.New("Shard Msg Section malformed")
	}
	bs := strings.Split(msg[sectionBegin+1:sectionEnd], ":::")
	bodies := []sections.MessageSectionWithSig{}
	for _, section := range bs {
		switch t := section[:4]; t {
		case ":CA:":
			assertionSection, err := parseContainedAssertion(section, msg[cn+4:zn], msg[zn+4:sectionBegin])
			if err != nil {
				return &sections.ZoneSection{}, err
			}
			assertionSection.Context = msg[cn+4 : zn]
			assertionSection.SubjectZone = msg[zn+4 : sectionBegin]
			bodies = append(bodies, assertionSection)
		case ":CS:":
			shardSection, err := parseContainedShard(section, msg[cn+4:zn], msg[zn+4:sectionBegin])
			if err != nil {
				return &sections.ZoneSection{}, err
			}
			bodies = append(bodies, shardSection)
		default:
			log.Warn("Unsupported message section type", "msgSection", section)
		}
	}
	signatures, err := parseSignatures(msg[sigBegin+1 : sigEnd])
	if err != nil {
		return &sections.ZoneSection{}, err
	}
	zoneSection := sections.ZoneSection{
		Context:     msg[cn+4 : zn],
		SubjectZone: msg[zn+4 : sectionBegin],
		Content:     bodies,
		Signatures:  signatures,
	}
	log.Debug("Successfully finished parsing signed zone")
	return &zoneSection, nil
}

//parseSignatures parses signatures where each signature has the format:
//:VF:<valid-from>:VU:<valid-until>:KS:<key-space>:KA:<key-algorithm>:SD:<signature-data>
func parseSignatures(msg string) ([]signature.Signature, error) {
	log.Debug("Parse Signature", "sig", msg)
	signatures := []signature.Signature{}
	if len(msg) == 0 {
		return signatures, nil
	}
	sigs := strings.Split(msg, ":VF:")[1:]
	for _, sig := range sigs {
		vu := strings.Index(sig, ":VU:")
		ks := strings.Index(sig, ":KS:")
		ka := strings.Index(sig, ":KA:")
		sd := strings.Index(sig, ":SD:")
		if vu == -1 || ks == -1 || ka == -1 || sd == -1 {
			log.Warn("signature malformed")
			return []signature.Signature{}, errors.New("signature malformed")
		}
		validSince, err := strconv.ParseInt(sig[:vu], 10, 64)
		if err != nil {
			log.Warn("signature's validSince malformed")
			return []signature.Signature{}, errors.New("signature's validSince malformed")
		}
		validUntil, err := strconv.ParseInt(sig[vu+4:ks], 10, 64)
		if err != nil {
			log.Warn("signature's validUntil malformed")
			return []signature.Signature{}, errors.New("signature's validUntil malformed")
		}
		keySpace, err := strconv.Atoi(sig[ks+4 : ka])
		if err != nil {
			log.Warn("signature's keyspace malformed")
			return []signature.Signature{}, errors.New("signature's cipher malformed")
		}
		algoType, err := strconv.Atoi(sig[ka+4 : sd])
		if err != nil {
			log.Warn("signature's algoID malformed")
			return []signature.Signature{}, errors.New("signature's cipher malformed")
		}
		sigData, err := hex.DecodeString(sig[sd+4:])
		if err != nil {
			return nil, err
		}
		//FIXME CFE use the correct type to store sigData into signature.Data.
		signature := signature.Signature{
			Algorithm:  algorithmTypes.SignatureAlgorithmType(algoType),
			Data:       sigData,
			ValidSince: validSince,
			ValidUntil: validUntil,
			KeySpace:   object.KeySpaceID(keySpace),
		}
		signatures = append(signatures, signature)
	}
	return signatures, nil
}

//parseQuery parses a query message section section
//:QU::VU:<valid-until>:CN:<context-name>:SN:<subject-name>:OT:<objtype>[<option1>:...:<option_n>]
func parseQuery(msg string, token token.Token) (*sections.QuerySection, error) {
	log.Debug("Parse Query", "query", msg)
	vu := strings.Index(msg, ":VU:")
	cn := strings.Index(msg, ":CN:")
	sn := strings.Index(msg, ":SN:")
	ot := strings.Index(msg, ":OT:")
	optsBegin := strings.Index(msg, "[")
	optsEnd := strings.Index(msg, "]")
	if vu == -1 || cn == -1 || sn == -1 || ot == -1 || optsBegin == -1 || optsEnd == -1 {
		log.Warn("Query Msg Section malformed")
		return &sections.QuerySection{}, errors.New("Query Msg Section malformed")
	}
	expires, err := strconv.ParseInt(msg[vu+4:cn], 10, 64)
	if err != nil {
		log.Warn("Valid Until malformed")
		return &sections.QuerySection{}, errors.New("Valid Until malformed")
	}
	objType, err := strconv.Atoi(msg[ot+4 : optsBegin])
	if err != nil {
		log.Warn("objType malformed")
		return &sections.QuerySection{}, errors.New("objType malformed")
	}
	var opts []sections.QueryOption
	for _, opt := range strings.Split(msg[optsBegin+1:optsEnd], ":") {
		val, err := strconv.Atoi(opt)
		if err != nil {
			opts = []sections.QueryOption{}
			break
		}
		opts = append(opts, sections.QueryOption(val))
	}
	return &sections.QuerySection{
		Token:   token,
		Expires: expires,
		Context: msg[cn+4 : sn],
		Name:    msg[sn+4 : ot],
		Type:    object.ObjectType(objType),
		Options: opts,
	}, nil
}

//parseNotification parses a notification message section section of the following format:
//:NO::TN:<token this notification refers to>:NT:<type>:ND:<data>
func parseNotification(msg string) (*sections.NotificationSection, error) {
	log.Debug("Parse Notification", "notification", msg)
	tn := strings.Index(msg, ":TN:")
	nt := strings.Index(msg, ":NT:")
	nd := strings.Index(msg, ":ND:")
	if tn == -1 || nt == -1 || nd == -1 {
		log.Warn("Notification Msg Section malformed")
		return &sections.NotificationSection{}, errors.New("Notification Msg Section malformed")
	}
	ntype, err := strconv.Atoi(msg[nt+4 : nd])
	if err != nil {
		log.Warn("Notification Type malformed")
		return &sections.NotificationSection{}, errors.New("notification type malformed")
	}
	token := [16]byte{}
	tokenEnc, err := hex.DecodeString(msg[tn+4 : nt])
	if err != nil {
		return &sections.NotificationSection{}, errors.New("notification token malformed")
	}
	copy(token[:], tokenEnc)
	return &sections.NotificationSection{
		Token: token.Token(token),
		Type:  sections.NotificationType(ntype),
		Data:  msg[nd+4:],
	}, nil
}*/
