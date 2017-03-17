package parser

import (
	"errors"
	"fmt"
	"rains/rainslib"
	"strconv"
	"strings"

	log "github.com/inconshreveable/log15"
)

//
type RainsMsgParser struct{}

//ParseByteSlice parses the byte slice to a RainsMessage according to the following formats:
//
//simple Signed Assertion: :SA::TM:<token>:CN:<context-name>:ZN:<zone-name>:SN:<subject-name>:OT:<object type>:OD:<object data>:sig:signature
//simple Query: :Q::TM:<token>:VU:<valid-until>:CN:<context-name>:SN:<subject-name>:OT:<objtype>
//simple Notification: :N::TM:<token of msg>:TN:<token this notification refers to>:NT:<type>:ND:<data>
//signature == :VF:<valid-from>:VU:<valid-until>:KA:<key-algorithm>:SD:<signature-data>
//NOT YET SUPPORTED
//simple Contained Assertion: :CA::SN:<subject-name>:OT:<object type>:OD:<object data>
//simple Contained Shard: :CS::RB:<range-begin>:RE:<range-end>[Contained Assertion*]
//simple Signed Shard: :SS::CN:<context-name>:ZN:<zone-name>:SN:<subject-name>:RB:<range-begin>:RE:<range-end>[Contained Assertion*][signature*]
//simple Zone: :Z::CN:<context-name>:ZN:<zone-name>[Contained Shard* | Contained Assertion*]
func (p RainsMsgParser) ParseByteSlice(message []byte) (rainslib.RainsMessage, error) {
	msg := string(message)
	t := msg[0:3]
	switch t {
	case ":SA:":
		return parseSignedAssertion(msg)
	case ":Q:":
		return parseQuery(msg)
	case ":N:":
		return parseNotification(msg)
	default:
		log.Warn("Unknown or Unsupported message type")
		return rainslib.RainsMessage{}, errors.New("Unknown or Unsupported message type")
	}
}

//ParseRainsMsg parses a RainsMessage to a byte slice representation according to the above specified formats:.
func (p RainsMsgParser) ParseRainsMsg(msg rainslib.RainsMessage) ([]byte, error) {
	return []byte{}, nil
}

//parseSignedAssertion parses a signed assertion message section body
//TODO CFE signature is not yet correctly parsed after my adoption of format
func parseSignedAssertion(msg string) (rainslib.RainsMessage, error) {
	log.Info("Received signed assertion", "msg", msg)
	tm := strings.Index(msg, ":TM:")
	cn := strings.Index(msg, ":CN:")
	zn := strings.Index(msg, ":ZN:")
	sn := strings.Index(msg, ":SN:")
	ot := strings.Index(msg, ":OT:")
	od := strings.Index(msg, ":OD:")
	vs := strings.Index(msg, ":VS:")
	vu := strings.Index(msg, ":VU:")
	ka := strings.Index(msg, ":KA:")
	sd := strings.Index(msg, ":SD:")
	sig := strings.Index(msg, ":sig:")
	if tm == -1 || zn == -1 || cn == -1 || sn == -1 || ot == -1 || od == -1 || vs == -1 || vu == -1 || ka == -1 || sd == -1 || sig == -1 {
		log.Warn("Assertion Msg Body malformated")
		return rainslib.RainsMessage{}, errors.New("Assertion Msg Body malformated")
	}
	objType, err := strconv.Atoi(msg[ot+4 : od])
	if err != nil {
		log.Warn("objType malformated")
		return rainslib.RainsMessage{}, errors.New("objType malformated")
	}
	validSince, err := strconv.Atoi(msg[vs+4 : vu])
	if err != nil {
		log.Warn("validSince malformated")
		return rainslib.RainsMessage{}, errors.New("validSince malformated")
	}
	validUntil, err := strconv.Atoi(msg[vu+4 : ka])
	if err != nil {
		log.Warn("validUntil malformated")
		return rainslib.RainsMessage{}, errors.New("validUntil malformated")
	}
	cipherType, err := strconv.Atoi(msg[ka+4 : sd])
	if err != nil {
		log.Warn("cipher malformated")
		return rainslib.RainsMessage{}, errors.New("cipher malformated")
	}
	object := rainslib.Object{Type: rainslib.ObjectType(objType), Value: msg[od+4 : vs]}
	signature := rainslib.Signature{Algorithm: rainslib.CipherType(cipherType), ValidSince: validSince, ValidUntil: validUntil, Data: []byte(msg[sd+4 : sig])}
	content := []rainslib.MessageBody{rainslib.AssertionBody{SubjectZone: msg[zn+4 : sn], Context: msg[cn+4 : zn], SubjectName: msg[sn+4 : ot],
		Content: object, Signature: signature}}
	return rainslib.RainsMessage{Token: rainslib.Token(msg[tm+4 : cn]), Content: content}, nil
}

//parseQuery parses a query message section body
func parseQuery(msg string) (rainslib.RainsMessage, error) {
	log.Info("Received query", "msg", msg)
	tm := strings.Index(msg, ":TM:")
	vu := strings.Index(msg, ":VU:")
	cn := strings.Index(msg, ":CN:")
	sn := strings.Index(msg, ":SN:")
	ot := strings.Index(msg, ":OT:")
	if tm == -1 || vu == -1 || cn == -1 || sn == -1 || ot == -1 {
		log.Warn("Query Msg Body malformated")
		return rainslib.RainsMessage{}, errors.New("Query Msg Body malformated")
	}
	expires, err := strconv.Atoi(msg[vu+4 : cn])
	if err != nil {
		log.Warn("Valid Until malformated")
		return rainslib.RainsMessage{}, errors.New("Valid Until malformated")
	}
	objType, err := strconv.Atoi(msg[ot+4 : len(msg)])
	if err != nil {
		log.Warn("objType malformated")
		return rainslib.RainsMessage{}, errors.New("objType malformated")
	}
	content := []rainslib.MessageBody{rainslib.QueryBody{Token: rainslib.Token(msg[tm+4 : vu]),
		Expires: expires, Context: msg[cn+4 : sn], SubjectName: msg[sn+4 : ot], Types: rainslib.ObjectType(objType)}}
	return rainslib.RainsMessage{Token: rainslib.Token(msg[tm+4 : vu]), Content: content}, nil
}

//parseNotification parses a notification message section body
func parseNotification(msg string) (rainslib.RainsMessage, error) {
	log.Info("Received notification", "msg", msg)
	//TODO CFE should we handle notifications in a separate buffer as we do not expect a lot of them and in case of
	//Capability hash not understood or Message too large we instantly want to resend it to reduce query latency.
	tm := strings.Index(msg, ":TM:")
	tn := strings.Index(msg, ":TN:")
	nt := strings.Index(msg, ":NT:")
	nd := strings.Index(msg, ":ND:")
	if tm == -1 || tn == -1 || nt == -1 || nd == -1 {
		log.Warn("Notification Msg Body malformated")
		return rainslib.RainsMessage{}, errors.New("Notification Msg Body malformated")
	}
	fmt.Println(msg[nt:nd])
	ntype, err := strconv.Atoi(msg[nt+4 : nd])
	if err != nil {
		log.Warn("Notification Type malformated")
		return rainslib.RainsMessage{}, errors.New("notification type malformated")
	}
	content := []rainslib.MessageBody{rainslib.NotificationBody{Token: rainslib.Token(msg[tn+4 : nt]), Type: rainslib.NotificationType(ntype), Data: msg[nd+4 : len(msg)]}}
	return rainslib.RainsMessage{Token: rainslib.Token(msg[tm+4 : tn]), Content: content}, nil
}
