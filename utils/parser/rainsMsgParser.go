package parser

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/rainslib"
)

//RainsMsgParser contains methods to convert rainsMessages as a byte slice to an internal representation and vice versa
type RainsMsgParser struct{}

//ParseByteSlice parses the byte slice to a RainsMessage according to the following format:
//It is ASSUMED that signature data does not contain the '[' char.
//RainsMessage format: <token>[MessageSection:::::...:::::MessageSection][signatures*]:cap:<capabilities
//Signed Assertion: :SA::CN:<context-name>:ZN:<zone-name>:SN:<subject-name>[(:OT:<object type>:OD:<object data>)*][signature*]
//Contained Assertion: :CA::SN:<subject-name>[:OT:<object type>:OD:<object data>][signature*]
//Signed Shard: :SS::CN:<context-name>:ZN:<zone-name>:RB:<range-begin>:RE:<range-end>[Contained Assertion*][signature*]
//Contained Shard: :CS::RB:<range-begin>:RE:<range-end>[Contained Assertion*][signature*]
//Zone: :SZ::CN:<context-name>:ZN:<zone-name>[(Contained Shard|Contained Assertion):::...:::(Contained Shard|Contained Assertion)][signature*]
//Query: :QU::VU:<valid-until>:CN:<context-name>:SN:<subject-name>:OT:<objtype>[<option1>:...:<option_n>]
//Notification: :NO::TN:<token this notification refers to>:NT:<type>:ND:<data>
//signature: :VF:<valid-from>:VU:<valid-until>:KS:<key-space>:KA:<key-algorithm>:SD:<signature-data>
func (p RainsMsgParser) ParseByteSlice(message []byte) (rainslib.RainsMessage, error) {
	msg := string(message)
	log.Info("Parse Rains Message", "message", msg)
	msgSectionBegin := strings.Index(msg, "[")
	msgSectionEnd := strings.LastIndex(msg, "[") - 1
	sigBegin := strings.LastIndex(msg, "[")
	sigEnd := strings.LastIndex(msg, "]")
	cap := strings.Index(msg, ":cap:")
	token, err := p.Token(message)
	if err != nil {
		return rainslib.RainsMessage{}, err
	}
	if msgSectionEnd == -2 || sigBegin == -1 || sigEnd == -1 || cap == -1 {
		log.Warn("Rains Message malformed")
		return rainslib.RainsMessage{Token: token}, errors.New("Rains Message malformed")
	}
	msgBodies, err := parseMessageBodies(msg[msgSectionBegin+1:msgSectionEnd], token)
	if err != nil {
		return rainslib.RainsMessage{Token: token}, err
	}
	signatures, err := parseSignatures(msg[sigBegin+1 : sigEnd])
	if err != nil {
		return rainslib.RainsMessage{Token: token}, err
	}
	capabilities := msg[cap+5 : len(msg)]
	return rainslib.RainsMessage{Token: token, Content: msgBodies, Signatures: signatures, Capabilities: capabilities}, nil
}

//ParseRainsMsg parses a RainsMessage to a byte slice representation with format:
//<token>[MessageSection:::::...:::::MessageSection][signatures*]:cap:<capabilities
func (p RainsMsgParser) ParseRainsMsg(m rainslib.RainsMessage) ([]byte, error) {
	msg := string(m.Token[:]) + "["
	for _, section := range m.Content {
		switch section := section.(type) {
		case *rainslib.AssertionSection:
			msg += revParseSignedAssertion(section)
		case *rainslib.ShardSection:
			msg += revParseSignedShard(section)
		case *rainslib.ZoneSection:
			msg += revParseSignedZone(section)
		case *rainslib.QuerySection:
			msg += revParseQuery(section)
		case *rainslib.NotificationSection:
			msg += revParseNotification(section)
		default:
			log.Warn("Unknown message section type", "type", fmt.Sprintf("%T", section), "section", section)
			return []byte{}, errors.New("Unknown message section type")
		}
	}
	return []byte(fmt.Sprintf("%s][%s]:cap:%s", msg, revParseSignature(m.Signatures), m.Capabilities)), nil
}

//Token returns the Token from the message represented as a byte slice with format:
//<token>[MessageSection:::::...:::::MessageSection][signatures*]:cap:<capabilities
func (p RainsMsgParser) Token(message []byte) (rainslib.Token, error) {
	msg := string(message)
	msgSectionBegin := strings.Index(msg, "[")
	if msgSectionBegin == -1 {
		log.Warn("Rains Message malformed, cannot extract token")
		return rainslib.Token{}, errors.New("Rains Message malformed, cannot extract token")
	}
	if msgSectionBegin > 16 {
		log.Error("Token is larger than 16 byte", "tokenSize", msgSectionBegin)
		return rainslib.Token{}, errors.New("Token is larger than 16 byte")
	}
	token := [16]byte{}
	copy(token[:msgSectionBegin], message[:msgSectionBegin])
	return rainslib.Token(token), nil
}

//RevParseSignedMsgSection parses an MessageSectionWithSig to a byte slice representation
func (p RainsMsgParser) RevParseSignedMsgSection(section rainslib.MessageSectionWithSig) (string, error) {
	switch section := section.(type) {
	case *rainslib.AssertionSection:
		return revParseSignedAssertion(section), nil
	case *rainslib.ShardSection:
		return revParseSignedShard(section), nil
	case *rainslib.ZoneSection:
		return revParseSignedZone(section), nil
	default:
		log.Warn("Unknown message section section type", "type", section)
		return "", errors.New("Unknown message section section type")
	}
}

//RevParseSignedAssertion parses a signed assertion to its string representation with format:
//:SA::CN:<context-name>:ZN:<zone-name>:SN:<subject-name>[:OT:<object type>:OD:<object data>][signature*]
func revParseSignedAssertion(a *rainslib.AssertionSection) string {
	assertion := fmt.Sprintf(":SA::CN:%s:ZN:%s:SN:%s[%s]][", a.Context, a.SubjectZone, a.SubjectName, revParseObjects(a.Content))
	return assertion + revParseSignature(a.Signatures) + "]"
}

//revParseContainedAssertion parses a contained assertion to its string representation with format:
//:SA::SN:<subject-name>[:OT:<object type>:OD:<object data>][signature*]
func revParseContainedAssertion(a *rainslib.AssertionSection) string {
	assertion := fmt.Sprintf(":CA::SN:%s:[%s]][", a.SubjectName, revParseObjects(a.Content))
	return assertion + revParseSignature(a.Signatures) + "]"
}

//revParseObjects parses objects to their string representation with format:
//(:OT:<object type>:OD:<object data>)*
func revParseObjects(content []rainslib.Object) string {
	objs := ""
	for _, obj := range content {
		objs += fmt.Sprintf(":OT:%v:OD:%v", obj.Type, obj.Value)
	}
	return objs
}

//RevParseSignedShard parses a signed shard to its string representation with format:
//:SS::CN:<context-name>:ZN:<zone-name>:RB:<range-begin>:RE:<range-end>[Contained Assertion*][signature*]
func revParseSignedShard(s *rainslib.ShardSection) string {
	shard := fmt.Sprintf(":SS::CN:%s:ZN:%s:RB:%s:RE:%s[", s.Context, s.SubjectZone, s.RangeFrom, s.RangeTo)
	for _, assertion := range s.Content {
		shard += revParseContainedAssertion(assertion)
	}
	return fmt.Sprintf("%s][%s]", shard, revParseSignature(s.Signatures))
}

//revParseContainedShard parses a signed shard to its string representation with format:
//:SS::RB:<range-begin>:RE:<range-end>[Contained Assertion*][signature*]
func revParseContainedShard(s *rainslib.ShardSection) string {
	shard := fmt.Sprintf(":CS::RB:%s:RE:%s[", s.RangeFrom, s.RangeTo)
	for _, assertion := range s.Content {
		shard += revParseContainedAssertion(assertion)
	}
	return fmt.Sprintf("%s][%s]", shard, revParseSignature(s.Signatures))
}

//RevParseSignedShard parses a signed shard to its string representation with format:
//:SZ::CN:<context-name>:ZN:<zone-name>[(Contained Shard|Contained Assertion):::...:::(Contained Shard|Contained Assertion)][signature*]
func revParseSignedZone(z *rainslib.ZoneSection) string {
	zone := fmt.Sprintf(":SZ::CN:%s:ZN:%s[", z.Context, z.SubjectZone)
	for _, section := range z.Content {
		switch section := section.(type) {
		case *rainslib.AssertionSection:
			zone += revParseContainedAssertion(section) + ":::"
		case *rainslib.ShardSection:
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
//signature: :VF:<valid-from>:VU:<valid-until>:KA:<key-algorithm>:SD:<signature-data>
func revParseSignature(sigs []rainslib.Signature) string {
	signatures := ""
	for _, sig := range sigs {
		signatures += fmt.Sprintf(":VF:%d:VU:%d:KA:%v:SD:%s", sig.ValidSince, sig.ValidUntil, sig.Algorithm, sig.Data)
	}
	return signatures
}

//revParseQuery parses a rains query to its string representation with format:
//:QU::VU:<valid-until>:CN:<context-name>:SN:<subject-name>:OT:<objtype>[<option1>:...:<option_n>]
func revParseQuery(q *rainslib.QuerySection) string {
	opts := ""
	for _, option := range q.Options {
		opts += fmt.Sprintf("%d:", option)
	}
	if len(q.Options) > 0 {
		opts = opts[:len(opts)-1]
	}
	return fmt.Sprintf(":QU::VU:%d:CN:%s:SN:%s:OT:%d[%s]", q.Expires, q.Context, q.Name, q.Types, opts)
}

//revParseNotification parses a rains notification to its string representation with format:
//:NO::TN:<token this notification refers to>:NT:<type>:ND:<data>
func revParseNotification(n *rainslib.NotificationSection) string {
	return fmt.Sprintf(":NO::TN:%s:NT:%v:ND:%s", n.Token, n.Type, n.Data)
}

//parseMessageBodies parses message section bodies according to their type (assertion, query, notification)
func parseMessageBodies(msg string, token rainslib.Token) ([]rainslib.MessageSection, error) {
	log.Info("Parse Message Bodies", "msgBodies", msg)
	parsedMsgBodies := []rainslib.MessageSection{}
	if len(msg) == 0 {
		return parsedMsgBodies, nil
	}
	msgBodies := strings.Split(msg, ":::::")
	for _, msgSection := range msgBodies {
		switch t := msgSection[0:4]; t {
		case ":SA:":
			assertionSection, err := parseSignedAssertion(msgSection)
			if err != nil {
				return []rainslib.MessageSection{}, err
			}
			parsedMsgBodies = append(parsedMsgBodies, assertionSection)
		case ":SS:":
			shardSection, err := parseSignedShard(msgSection)
			if err != nil {
				return []rainslib.MessageSection{}, err
			}
			parsedMsgBodies = append(parsedMsgBodies, shardSection)
		case ":SZ:":
			zoneSection, err := parseSignedZone(msgSection)
			if err != nil {
				return []rainslib.MessageSection{}, err
			}
			parsedMsgBodies = append(parsedMsgBodies, zoneSection)
		case ":QU:":
			querySection, err := parseQuery(msgSection, token)
			if err != nil {
				return []rainslib.MessageSection{}, err
			}
			parsedMsgBodies = append(parsedMsgBodies, querySection)
		case ":NO:":
			notificationSection, err := parseNotification(msgSection)
			if err != nil {
				return []rainslib.MessageSection{}, err
			}
			parsedMsgBodies = append(parsedMsgBodies, notificationSection)
		default:
			log.Warn("Unknown or Unsupported message type", "type", t)
			return []rainslib.MessageSection{}, errors.New("Unknown or Unsupported message type")
		}
	}
	return parsedMsgBodies, nil
}

//parseSignedAssertion parses a signed assertion message section with format:
//:SA::CN:<context-name>:ZN:<zone-name>:SN:<subject-name>:OT:<object type>:OD:<object data>[signature*]
func parseSignedAssertion(msg string) (*rainslib.AssertionSection, error) {
	log.Info("Parse Signed Assertion", "assertion", msg)
	cn := strings.Index(msg, ":CN:")
	zn := strings.Index(msg, ":ZN:")
	sn := strings.Index(msg, ":SN:")
	objBegin := strings.Index(msg, "[")
	objEnd := strings.Index(msg, "]")
	sigBegin := strings.LastIndex(msg, "[")
	sigEnd := strings.LastIndex(msg, "]")
	if cn == -1 || zn == -1 || sn == -1 || objBegin == -1 || objEnd == -1 || sigBegin == -1 || sigEnd == -1 {
		log.Warn("Assertion Msg Section malformed")
		return &rainslib.AssertionSection{}, errors.New("Assertion Msg Section malformed")
	}
	objects, err := parseObjects(msg[objBegin+1 : objEnd])
	if err != nil {
		return &rainslib.AssertionSection{}, err
	}
	signatures, err := parseSignatures(msg[sigBegin+1 : sigEnd])
	if err != nil {
		return &rainslib.AssertionSection{}, err
	}
	assertionSection := rainslib.AssertionSection{Context: msg[cn+4 : zn], SubjectZone: msg[zn+4 : sn], SubjectName: msg[sn+4 : objBegin], Content: objects, Signatures: signatures}
	return &assertionSection, nil
}

//parseContainedAssertion parses a contained assertion message section with format:
//:CA::SN:<subject-name>:OT:<object type>:OD:<object data>[signature*]
func parseContainedAssertion(msg, context, subjectZone string) (*rainslib.AssertionSection, error) {
	log.Info("Parse Contained Assertion", "assertion", msg)
	sn := strings.Index(msg, ":SN:")
	objBegin := strings.Index(msg, "[")
	objEnd := strings.Index(msg, "]")
	sigBegin := strings.Index(msg, "[")
	sigEnd := strings.Index(msg, "]")
	if sn == -1 || objBegin == -1 || objEnd == -1 || sigBegin == -1 || sigEnd == -1 {
		log.Warn("Assertion Msg Section malformed")
		return &rainslib.AssertionSection{}, errors.New("Assertion Msg Section malformed")
	}
	objects, err := parseObjects(msg[objBegin+1 : objEnd])
	if err != nil {
		return &rainslib.AssertionSection{}, err
	}
	if err != nil {
		log.Warn("objType malformed")
		return &rainslib.AssertionSection{}, errors.New("objType malformed")
	}
	signatures, err := parseSignatures(msg[sigBegin+1 : sigEnd])
	if err != nil {
		return &rainslib.AssertionSection{}, err
	}
	assertionSection := rainslib.AssertionSection{
		Context:     context,
		SubjectZone: subjectZone,
		SubjectName: msg[sn+4 : objBegin],
		Content:     objects,
		Signatures:  signatures,
	}
	return &assertionSection, nil
}

//parseObjects parses objects with format:
//(:OT:<object type>:OD:<object data>)*
func parseObjects(inputObjects string) ([]rainslib.Object, error) {
	log.Info("Parse Objects", "objects", inputObjects)
	objects := []rainslib.Object{}
	if len(inputObjects) == 0 {
		return objects, nil
	}
	objs := strings.Split(inputObjects, ":OT:")[1:]
	for _, obj := range objs {
		od := strings.Index(obj, ":OD:")
		if od == -1 {
			log.Warn("object malformed", "object", obj)
			return []rainslib.Object{}, errors.New("object malformed")
		}
		objectType, err := strconv.Atoi(obj[:od])
		if err != nil {
			log.Warn("Object's objectType malformed")
			return []rainslib.Object{}, errors.New("Object's objectType malformed")
		}

		object := rainslib.Object{Type: rainslib.ObjectType(objectType), Value: obj[od:]}
		objects = append(objects, object)
	}
	return objects, nil
}

//parseSignedShard parses a signed shard message section with format:
//:SS::CN:<context-name>:ZN:<zone-name>:RB:<range-begin>:RE:<range-end>[ContainedAssertion*][signature*]
func parseSignedShard(msg string) (*rainslib.ShardSection, error) {
	log.Info("Parse Signed Shard", "Shard", msg)
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
		return &rainslib.ShardSection{}, errors.New("Shard Msg Section malformed")
	}
	assertions := strings.Split(msg[assertBegin+1:assertEnd], ":CA:")[1:]
	assertionBodies := []*rainslib.AssertionSection{}
	for _, assertion := range assertions {
		assertionSection, err := parseContainedAssertion(assertion, msg[cn+4:zn], msg[zn+4:rb])
		if err != nil {
			return &rainslib.ShardSection{}, err
		}
		assertionSection.Context = msg[cn+4 : zn]
		assertionSection.SubjectZone = msg[zn+4 : rb]
		assertionBodies = append(assertionBodies, assertionSection)
	}
	signatures, err := parseSignatures(msg[sigBegin+1 : sigEnd])
	if err != nil {
		return &rainslib.ShardSection{}, err
	}
	shardSection := rainslib.ShardSection{
		Context:     msg[cn+4 : zn],
		SubjectZone: msg[zn+4 : rb],
		RangeFrom:   msg[rb+4 : re],
		RangeTo:     msg[re+4 : assertBegin],
		Content:     assertionBodies,
		Signatures:  signatures,
	}
	return &shardSection, nil
}

//parseContainedShard parses a contained shard message section with format:
//:CS::RB:<range-begin>:RE:<range-end>[ContainedAssertion*][signature*]
func parseContainedShard(msg, context, subjectZone string) (*rainslib.ShardSection, error) {
	log.Info("Parse Contained Shard", "shard", msg)
	rb := strings.Index(msg, ":RB:")
	re := strings.Index(msg, ":RE:")
	assertBegin := strings.Index(msg, "[")
	assertEnd := strings.LastIndex(msg, "[") - 1
	sigBegin := strings.LastIndex(msg, "[")
	sigEnd := strings.LastIndex(msg, "]")
	if rb == -1 || re == -1 || assertBegin == -1 || assertEnd == -2 || sigBegin == -1 || sigEnd == -1 {
		log.Warn("Shard Msg Section malformed")
		return &rainslib.ShardSection{}, errors.New("Shard Msg Section malformed")
	}
	assertions := strings.Split(msg[assertBegin+1:assertEnd], ":CA:")[1:]
	assertionBodies := []*rainslib.AssertionSection{}
	for _, assertion := range assertions {
		assertionSection, err := parseContainedAssertion(assertion, context, subjectZone)
		if err != nil {
			return &rainslib.ShardSection{}, err
		}
		assertionBodies = append(assertionBodies, assertionSection)
	}
	signatures, err := parseSignatures(msg[sigBegin+1 : sigEnd])
	if err != nil {
		return &rainslib.ShardSection{}, err
	}
	shardSection := rainslib.ShardSection{
		Context:     context,
		SubjectZone: subjectZone,
		RangeFrom:   msg[rb+4 : re],
		RangeTo:     msg[re+4 : assertBegin],
		Content:     assertionBodies,
		Signatures:  signatures,
	}
	return &shardSection, nil
}

//parseSignedZone parses a signed zone message section with format:
//:SZ::CN:<context-name>:ZN:<zone-name>[(Contained Shard|Contained Assertion):::...:::(Contained Shard|Contained Assertion)][signature*]
func parseSignedZone(msg string) (*rainslib.ZoneSection, error) {
	log.Info("Parse Signed Zone", "zone", msg)
	cn := strings.Index(msg, ":CN:")
	zn := strings.Index(msg, ":ZN:")
	sectionBegin := strings.Index(msg, "[")
	sectionEnd := strings.LastIndex(msg, "[") - 1
	sigBegin := strings.LastIndex(msg, "[")
	sigEnd := strings.LastIndex(msg, "]")
	if zn == -1 || cn == -1 || sectionBegin == -1 || sectionEnd == -2 || sigBegin == -1 || sigEnd == -1 {
		log.Warn("Shard Msg Section malformed")
		return &rainslib.ZoneSection{}, errors.New("Shard Msg Section malformed")
	}
	bs := strings.Split(msg[sectionBegin+1:sectionEnd], ":::")
	bodies := []rainslib.MessageSectionWithSig{}
	for _, section := range bs {
		switch t := section[:4]; t {
		case ":CA:":
			assertionSection, err := parseContainedAssertion(section, msg[cn+4:zn], msg[zn+4:sectionBegin])
			if err != nil {
				return &rainslib.ZoneSection{}, err
			}
			assertionSection.Context = msg[cn+4 : zn]
			assertionSection.SubjectZone = msg[zn+4 : sectionBegin]
			bodies = append(bodies, assertionSection)
		case ":CS:":
			shardSection, err := parseContainedShard(section, msg[cn+4:zn], msg[zn+4:sectionBegin])
			if err != nil {
				return &rainslib.ZoneSection{}, err
			}
			bodies = append(bodies, shardSection)
		default:
			log.Warn("Unsupported message section type", "msgSection", section)
		}
	}
	signatures, err := parseSignatures(msg[sigBegin+1 : sigEnd])
	if err != nil {
		return &rainslib.ZoneSection{}, err
	}
	zoneSection := rainslib.ZoneSection{
		Context:     msg[cn+4 : zn],
		SubjectZone: msg[zn+4 : sectionBegin],
		Content:     bodies,
		Signatures:  signatures,
	}
	return &zoneSection, nil
}

//parseSignatures parses signatures where each signature has the format:
//:VF:<valid-from>:VU:<valid-until>:KS:<key-space>:KA:<key-algorithm>:SD:<signature-data>
func parseSignatures(msg string) ([]rainslib.Signature, error) {
	log.Info("Parse Signature", "sig", msg)
	signatures := []rainslib.Signature{}
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
			return []rainslib.Signature{}, errors.New("signature malformed")
		}
		validSince, err := strconv.Atoi(sig[:vu])
		if err != nil {
			log.Warn("signature's validSince malformed")
			return []rainslib.Signature{}, errors.New("signature's validSince malformed")
		}
		validUntil, err := strconv.Atoi(sig[vu+4 : ks])
		if err != nil {
			log.Warn("signature's validUntil malformed")
			return []rainslib.Signature{}, errors.New("signature's validUntil malformed")
		}
		keySpace, err := strconv.Atoi(sig[ks+4 : ka])
		if err != nil {
			log.Warn("signature's keyspace malformed")
			return []rainslib.Signature{}, errors.New("signature's cipher malformed")
		}
		algoType, err := strconv.Atoi(sig[ka+4 : sd])
		if err != nil {
			log.Warn("signature's algoID malformed")
			return []rainslib.Signature{}, errors.New("signature's cipher malformed")
		}
		signature := rainslib.Signature{
			Algorithm:  rainslib.SignatureAlgorithmType(algoType),
			Data:       []byte(sig[sd+4 : len(sig)]),
			ValidSince: validSince,
			ValidUntil: validUntil,
			KeySpace:   rainslib.KeySpaceID(keySpace),
		}
		signatures = append(signatures, signature)
	}
	return signatures, nil
}

//parseQuery parses a query message section section
//:QU::VU:<valid-until>:CN:<context-name>:SN:<subject-name>:OT:<objtype>[<option1>:...:<option_n>]
func parseQuery(msg string, token rainslib.Token) (*rainslib.QuerySection, error) {
	log.Info("Parse Query", "query", msg)
	vu := strings.Index(msg, ":VU:")
	cn := strings.Index(msg, ":CN:")
	sn := strings.Index(msg, ":SN:")
	ot := strings.Index(msg, ":OT:")
	optsBegin := strings.Index(msg, "[")
	optsEnd := strings.Index(msg, "]")
	if vu == -1 || cn == -1 || sn == -1 || ot == -1 || optsBegin == -1 || optsEnd == -1 {
		log.Warn("Query Msg Section malformed")
		return &rainslib.QuerySection{}, errors.New("Query Msg Section malformed")
	}
	expires, err := strconv.Atoi(msg[vu+4 : cn])
	if err != nil {
		log.Warn("Valid Until malformed")
		return &rainslib.QuerySection{}, errors.New("Valid Until malformed")
	}
	objType, err := strconv.Atoi(msg[ot+4 : optsBegin])
	if err != nil {
		log.Warn("objType malformed")
		return &rainslib.QuerySection{}, errors.New("objType malformed")
	}
	var opts []rainslib.QueryOption
	for _, opt := range strings.Split(msg[optsBegin+1:optsEnd], ":") {
		val, err := strconv.Atoi(opt)
		if err != nil {
			opts = []rainslib.QueryOption{}
			break
		}
		opts = append(opts, rainslib.QueryOption(val))
	}
	return &rainslib.QuerySection{
		Token:   token,
		Expires: expires,
		Context: msg[cn+4 : sn],
		Name:    msg[sn+4 : ot],
		Types:   rainslib.ObjectType(objType),
		Options: opts,
	}, nil
}

//parseNotification parses a notification message section section of the following format:
//:NO::TN:<token this notification refers to>:NT:<type>:ND:<data>
func parseNotification(msg string) (*rainslib.NotificationSection, error) {
	log.Info("Parse Notification", "notification", msg)
	tn := strings.Index(msg, ":TN:")
	nt := strings.Index(msg, ":NT:")
	nd := strings.Index(msg, ":ND:")
	if tn == -1 || nt == -1 || nd == -1 {
		log.Warn("Notification Msg Section malformed")
		return &rainslib.NotificationSection{}, errors.New("Notification Msg Section malformed")
	}
	ntype, err := strconv.Atoi(msg[nt+4 : nd])
	if err != nil {
		log.Warn("Notification Type malformed")
		return &rainslib.NotificationSection{}, errors.New("notification type malformed")
	}
	token := [16]byte{}
	copy(token[:nt-tn-4], msg[tn+4:nt])
	return &rainslib.NotificationSection{
		Token: rainslib.Token(token),
		Type:  rainslib.NotificationType(ntype),
		Data:  msg[nd+4 : len(msg)],
	}, nil
}
