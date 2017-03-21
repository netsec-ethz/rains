package parser

import (
	"errors"
	"fmt"
	"rains/rainslib"
	"strconv"
	"strings"

	log "github.com/inconshreveable/log15"
)

//RainsMsgParser contains methods to convert rainsMessages as a byte slice to an internal representation and vice versa
type RainsMsgParser struct{}

//ParseByteSlice parses the byte slice to a RainsMessage according to the following format:
//<token>[MessageBody][signatures*]:cap:<capabilities>
//
//simple RainsMessage format: <token>[MessageBody*][signatures*]:cap:<capabilities
//simple Signed Assertion: :SA::CN:<context-name>:ZN:<zone-name>:SN:<subject-name>:OT:<object type>:OD:<object data>[signature*]
//simple Signed Shard: :SS::CN:<context-name>:ZN:<zone-name>:RB:<range-begin>:RE:<range-end>[Contained Assertion*][signature*]
//simple Query: :QU::VU:<valid-until>:CN:<context-name>:SN:<subject-name>:OT:<objtype>[<option1>:...:<option_n>]
//simple Notification: :NO::TN:<token this notification refers to>:NT:<type>:ND:<data>
//signature: :VF:<valid-from>:VU:<valid-until>:KS:<key-space>:KA:<key-algorithm>:SD:<signature-data>
//NOT YET SUPPORTED
//simple Contained Assertion: :CA::SN:<subject-name>:OT:<object type>:OD:<object data>
//simple Contained Shard: :CS::RB:<range-begin>:RE:<range-end>[Contained Assertion*]
//simple Zone: :SZ::CN:<context-name>:ZN:<zone-name>[Contained Shard* | Contained Assertion*]
func (p RainsMsgParser) ParseByteSlice(message []byte) (rainslib.RainsMessage, error) {
	msg := string(message)
	log.Info("Parse Rains Message", "Message", msg)
	msgBodyBegin := strings.Index(msg, "[")
	msgBodyEnd := strings.LastIndex(msg, "[") - 1
	sigBegin := strings.LastIndex(msg, "[")
	sigEnd := strings.LastIndex(msg, "]")
	cap := strings.Index(msg, ":cap:")
	token, err := p.Token(message)
	if err != nil {
		return rainslib.RainsMessage{}, err
	}
	if msgBodyEnd == -2 || sigBegin == -1 || sigEnd == -1 || cap == -1 {
		log.Warn("Parser: Rains Message malformated")
		return rainslib.RainsMessage{Token: token}, errors.New("Rains Message malformated")
	}
	msgBodies, err := parseMessageBodies(msg[msgBodyBegin+1:msgBodyEnd], token)
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
//<token>[MessageBody][signatures*]:cap:<capabilities>
func (p RainsMsgParser) ParseRainsMsg(m rainslib.RainsMessage) ([]byte, error) {
	msg := string(m.Token) + "["
	for _, body := range m.Content {
		switch body := body.(type) {
		case *rainslib.AssertionBody:
			msg += p.RevParseSignedAssertion(body)
		case *rainslib.ShardBody:
			msg += revParseSignedShard(body, p)
		case *rainslib.QueryBody:
			msg += revParseQuery(body)
		case *rainslib.NotificationBody:
			msg += revParseNotification(body)
		default:
			log.Warn("Parser: Unknown message section body type", "type", body)
			return []byte{}, errors.New("Unknown message section body type")
		}
	}
	return []byte(fmt.Sprintf("%s][%s]:cap:%s", msg, revParseSignature(m.Signatures), m.Capabilities)), nil
}

//Token returns the Token from the message represented as a byte slice with format:
//<token>[MessageBody][signatures*]:cap:<capabilities>
func (p RainsMsgParser) Token(message []byte) (rainslib.Token, error) {
	msg := string(message)
	msgBodyBegin := strings.Index(msg, "[")
	if msgBodyBegin == -1 {
		log.Warn("Parser: Rains Message malformated, cannot extract token")
		return rainslib.Token{}, errors.New("Rains Message malformated, cannot extract token")
	}
	if msgBodyBegin > 32 {
		log.Error("Parser: Token is larger than 32 byte", "TokenSize", msgBodyBegin)
		return rainslib.Token{}, errors.New("Token is larger than 32 byte")
	}
	return rainslib.Token(msg[:msgBodyBegin]), nil
}

//RevParseSignedAssertion parses a signed assertion to its string representation with format:
//:SA::CN:<context-name>:ZN:<zone-name>:SN:<subject-name>:OT:<object type>:OD:<object data>[signature*]
func (p RainsMsgParser) RevParseSignedAssertion(a *rainslib.AssertionBody) string {
	assertion := fmt.Sprintf(":SA::CN:%s:ZN:%s:SN:%s:OT:%v:OD:%v[", a.Context, a.SubjectZone, a.SubjectName, a.Content.Type, a.Content.Value)
	return assertion + revParseSignature(a.Signatures) + "]"
}

//revParseSignedShard parses a signed shard to its string representation with format:
//:SS::CN:<context-name>:ZN:<zone-name>:RB:<range-begin>:RE:<range-end>[Contained Assertion*][signature*]
func revParseSignedShard(s *rainslib.ShardBody, p RainsMsgParser) string {
	shard := fmt.Sprintf(":SS::CN:%s:ZN:%s:RB:%s:RE:%s[", s.Context, s.SubjectZone, s.RangeFrom, s.RangeTo)
	for _, assertion := range s.Content {
		shard += p.RevParseSignedAssertion(assertion)
	}
	return fmt.Sprintf("%s][%s]", shard, revParseSignature(s.Signatures))
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
//:QU::VU:<valid-until>:CN:<context-name>:SN:<subject-name>:OT:<objtype>
func revParseQuery(q *rainslib.QueryBody) string {
	return fmt.Sprintf(":QU::VU:%d:CN:%s:SN:%s:OT:%d", q.Expires, q.Context, q.SubjectName, q.Types)
}

//revParseNotification parses a rains notification to its string representation with format:
//:NO::TN:<token this notification refers to>:NT:<type>:ND:<data>
func revParseNotification(n *rainslib.NotificationBody) string {
	return fmt.Sprintf(":NO::TN:%s:NT:%v:ND:%s", n.Token, n.Type, n.Data)
}

//parseMessageBodies parses message section bodies according to their type (assertion, query, notification)
func parseMessageBodies(msg string, token rainslib.Token) ([]rainslib.MessageBody, error) {
	log.Info("Parse Message Bodies", "MsgBodies", msg)
	parsedMsgBodies := []rainslib.MessageBody{}
	if len(msg) == 0 {
		return parsedMsgBodies, nil
	}
	//TODO CFE For now we assume we have only 1 message section body per rains message.
	msgBodies := []string{msg}
	for _, msgBody := range msgBodies {
		t := msgBody[0:4]
		switch t {
		case ":SA:":
			assertionBody, err := parseSignedAssertion(msgBody)
			if err != nil {
				return []rainslib.MessageBody{}, err
			}
			parsedMsgBodies = append(parsedMsgBodies, assertionBody)
		case ":SS:":
			shardBody, err := parseSignedShard(msgBody)
			if err != nil {
				return []rainslib.MessageBody{}, err
			}
			parsedMsgBodies = append(parsedMsgBodies, shardBody)
		case ":QU:":
			queryBody, err := parseQuery(msgBody, token)
			if err != nil {
				return []rainslib.MessageBody{}, err
			}
			parsedMsgBodies = append(parsedMsgBodies, queryBody)
		case ":NO:":
			notificationBody, err := parseNotification(msgBody)
			if err != nil {
				return []rainslib.MessageBody{}, err
			}
			parsedMsgBodies = append(parsedMsgBodies, notificationBody)
		default:
			log.Warn("Parser: Unknown or Unsupported message type", "type", t)
			return []rainslib.MessageBody{}, errors.New("Unknown or Unsupported message type")
		}
	}
	return parsedMsgBodies, nil
}

//parseSignedAssertion parses a signed assertion message section body with format:
//:SA::CN:<context-name>:ZN:<zone-name>:SN:<subject-name>:OT:<object type>:OD:<object data>[signature*]
func parseSignedAssertion(msg string) (*rainslib.AssertionBody, error) {
	log.Info("Parse Signed Assertion", "Assertion", msg)
	cn := strings.Index(msg, ":CN:")
	zn := strings.Index(msg, ":ZN:")
	sn := strings.Index(msg, ":SN:")
	ot := strings.Index(msg, ":OT:")
	od := strings.Index(msg, ":OD:")
	sigBegin := strings.Index(msg, "[")
	sigEnd := strings.Index(msg, "]")
	if cn == -1 || zn == -1 || sn == -1 || ot == -1 || od == -1 || sigBegin == -1 || sigEnd == -1 {
		log.Warn("Parser: Assertion Msg Body malformated")
		return &rainslib.AssertionBody{}, errors.New("Assertion Msg Body malformated")
	}
	objType, err := strconv.Atoi(msg[ot+4 : od])
	if err != nil {
		log.Warn("Parser: objType malformated")
		return &rainslib.AssertionBody{}, errors.New("objType malformated")
	}
	signatures, err := parseSignatures(msg[sigBegin+1 : sigEnd])
	if err != nil {
		return &rainslib.AssertionBody{}, err
	}
	object := rainslib.Object{Type: rainslib.ObjectType(objType), Value: msg[od+4 : sigBegin]}
	assertionBody := rainslib.AssertionBody{Context: msg[cn+4 : zn], SubjectZone: msg[zn+4 : sn], SubjectName: msg[sn+4 : ot], Content: object, Signatures: signatures}
	return &assertionBody, nil
}

//parseSignedShard parses a signed shard message section body with format:
//TODO CFE replace signedassertions with contained assertions
//:SS::CN:<context-name>:ZN:<zone-name>:RB:<range-begin>:RE:<range-end>[SignedAssertion*][signature*]
func parseSignedShard(msg string) (*rainslib.ShardBody, error) {
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
		log.Warn("Parser: Shard Msg Body malformated")
		return &rainslib.ShardBody{}, errors.New("Shard Msg Body malformated")
	}
	//TODO CFE change this to contained assertions when supported
	assertions := strings.Split(msg[assertBegin+1:assertEnd], ":SA:")[1:]
	assertionBodies := []*rainslib.AssertionBody{}
	for _, assertion := range assertions {
		assertionBody, err := parseSignedAssertion(assertion)
		if err != nil {
			return &rainslib.ShardBody{}, err
		}
		assertionBodies = append(assertionBodies, assertionBody)
	}
	signatures, err := parseSignatures(msg[sigBegin+1 : sigEnd])
	if err != nil {
		return &rainslib.ShardBody{}, err
	}
	shardBody := rainslib.ShardBody{Context: msg[cn+4 : zn], SubjectZone: msg[zn+4 : rb], RangeFrom: msg[rb+4 : re], RangeTo: msg[re+4 : assertBegin],
		Content: assertionBodies, Signatures: signatures}
	return &shardBody, nil
}

//parseSignatures parses signatures where each signature has the format:
//:VF:<valid-from>:VU:<valid-until>:KS:<key-space>:KA:<key-algorithm>:SD:<signature-data>
func parseSignatures(msg string) ([]rainslib.Signature, error) {
	log.Info("Parse Signature", "Sig", msg)
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
			log.Warn("Parser: signature malformated")
			return []rainslib.Signature{}, errors.New("signature malformated")
		}
		validSince, err := strconv.Atoi(sig[:vu])
		if err != nil {
			log.Warn("Parser: signature's validSince malformated")
			return []rainslib.Signature{}, errors.New("signature's validSince malformated")
		}
		validUntil, err := strconv.Atoi(sig[vu+4 : ks])
		if err != nil {
			log.Warn("Parser: signature's validUntil malformated")
			return []rainslib.Signature{}, errors.New("signature's validUntil malformated")
		}
		keySpace, err := strconv.Atoi(sig[ks+4 : ka])
		if err != nil {
			log.Warn("Parser: signature's keyspace malformated")
			return []rainslib.Signature{}, errors.New("signature's cipher malformated")
		}
		algoType, err := strconv.Atoi(sig[ka+4 : sd])
		if err != nil {
			log.Warn("Parser: signature's algoID malformated")
			return []rainslib.Signature{}, errors.New("signature's cipher malformated")
		}
		signature := rainslib.Signature{Algorithm: rainslib.AlgorithmType(algoType), Data: []byte(sig[sd+4 : len(sig)]), ValidSince: validSince, ValidUntil: validUntil,
			KeySpace: rainslib.KeySpaceID(keySpace)}
		signatures = append(signatures, signature)
	}
	return signatures, nil
}

//parseQuery parses a query message section body
//:QU::VU:<valid-until>:CN:<context-name>:SN:<subject-name>:OT:<objtype>[<option1>:...:<option_n>]
func parseQuery(msg string, token rainslib.Token) (*rainslib.QueryBody, error) {
	log.Info("Parse Query", "Query", msg)
	vu := strings.Index(msg, ":VU:")
	cn := strings.Index(msg, ":CN:")
	sn := strings.Index(msg, ":SN:")
	ot := strings.Index(msg, ":OT:")
	optsBegin := strings.Index(msg, "[")
	optsEnd := strings.Index(msg, "]")
	if vu == -1 || cn == -1 || sn == -1 || ot == -1 || optsBegin == -1 || optsEnd == -1 {
		log.Warn("Parser: Query Msg Body malformated")
		return &rainslib.QueryBody{}, errors.New("Query Msg Body malformated")
	}
	expires, err := strconv.Atoi(msg[vu+4 : cn])
	if err != nil {
		log.Warn("Parser: Valid Until malformated")
		return &rainslib.QueryBody{}, errors.New("Valid Until malformated")
	}
	objType, err := strconv.Atoi(msg[ot+4 : optsBegin])
	if err != nil {
		log.Warn("Parser: objType malformated")
		return &rainslib.QueryBody{}, errors.New("objType malformated")
	}
	var opts []rainslib.QueryOptions
	for _, opt := range strings.Split(msg[optsBegin+1:optsEnd], ":") {
		val, err := strconv.Atoi(opt)
		if err != nil {
			opts = []rainslib.QueryOptions{}
			break
		}
		opts = append(opts, rainslib.QueryOptions(val))
	}
	return &rainslib.QueryBody{Token: token, Expires: expires, Context: msg[cn+4 : sn], SubjectName: msg[sn+4 : ot], Types: rainslib.ObjectType(objType), Options: opts}, nil
}

//parseNotification parses a notification message section body of the following format:
//:NO::TN:<token this notification refers to>:NT:<type>:ND:<data>
func parseNotification(msg string) (*rainslib.NotificationBody, error) {
	log.Info("Parse Notification", "Notification", msg)
	tn := strings.Index(msg, ":TN:")
	nt := strings.Index(msg, ":NT:")
	nd := strings.Index(msg, ":ND:")
	if tn == -1 || nt == -1 || nd == -1 {
		log.Warn("Parser: Notification Msg Body malformated")
		return &rainslib.NotificationBody{}, errors.New("Notification Msg Body malformated")
	}
	ntype, err := strconv.Atoi(msg[nt+4 : nd])
	if err != nil {
		log.Warn("Parser: Notification Type malformated")
		return &rainslib.NotificationBody{}, errors.New("notification type malformated")
	}
	return &rainslib.NotificationBody{Token: rainslib.Token(msg[tn+4 : nt]), Type: rainslib.NotificationType(ntype), Data: msg[nd+4 : len(msg)]}, nil
}
