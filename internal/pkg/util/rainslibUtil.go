package util

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/keys"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/signature"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/scionproto/scion/go/lib/addr"
	"golang.org/x/crypto/ed25519"
)

func init() {
	gob.Register(keys.PublicKey{})
	gob.RegisterName("ed25519.PublicKey", ed25519.PublicKey{})
	gob.Register(&section.Assertion{})
	gob.Register(&section.Shard{})
	gob.Register(&section.Pshard{})
	gob.Register(&section.Zone{})
	gob.Register(object.ServiceInfo{})
	gob.Register(object.Certificate{})
	gob.Register(object.Name{})
	gob.Register(net.IP{})
	gob.Register(&object.SCIONAddress{})
	gob.Register(addr.HostIPv4{})
	gob.Register(addr.HostIPv6{})
}

//MaxCacheValidity defines the maximum duration each section containing signatures can be valid, starting from time.Now()
type MaxCacheValidity struct {
	AssertionValidity time.Duration
	ShardValidity     time.Duration
	PshardValidity    time.Duration
	ZoneValidity      time.Duration
}

//MsgSectionSender contains the message section section and connection infos about the sender
type MsgSectionSender struct {
	Sender   net.Addr
	Sections []section.Section
	Token    token.Token
}

//SectionWithSigSender contains a section with a signature and connection infos about the sender
type SectionWithSigSender struct {
	Sender   net.Addr
	Sections []section.WithSigForward
	Token    token.Token
}

//Save stores the object to the file located at the specified path gob encoded.
func Save(path string, object interface{}) error {
	file, err := os.Create(path)
	defer file.Close()
	if err == nil {
		encoder := gob.NewEncoder(file)
		err = encoder.Encode(object)
	}
	return err
}

//Load fetches the gob encoded object from the file located at path. Make sure that all types that
//are behind an interface are registered in the init method.
func Load(path string, object interface{}) error {
	file, err := os.Open(path)
	defer file.Close()
	if err != nil {
		log.Error("Was not able to open file", "path", path, "error", err)
		return err
	}
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(object)
	if err != nil {
		log.Error("Was not able to decode file.", "path", path, "error", err)
	}
	return err
}

//NewQueryMessage creates a new message containing a query body with values obtained from the input parameter
func NewQueryMessage(name, context string, expTime int64, objType []object.Type,
	queryOptions []query.Option, token token.Token) message.Message {
	query := query.Name{
		Context:    context,
		Name:       name,
		Expiration: expTime,
		Types:      objType,
		Options:    queryOptions,
	}
	return message.Message{Token: token, Content: []section.Section{&query}}
}

//NewNotificationsMessage creates a new message containing notification bodies with values obtained from the input parameter
func NewNotificationsMessage(tokens []token.Token, types []section.NotificationType, data []string) (message.Message, error) {
	if len(tokens) != len(types) || len(types) != len(data) {
		log.Warn("input slices have not the same length", "tokenLen", len(tokens), "typesLen", len(types), "dataLen", len(data))
		return message.Message{}, errors.New("input slices have not the same length")
	}
	msg := message.Message{Token: token.New(), Content: []section.Section{}}
	for i := range tokens {
		notification := &section.Notification{
			Token: tokens[i],
			Type:  types[i],
			Data:  data[i],
		}
		msg.Content = append(msg.Content, notification)
	}
	return msg, nil
}

//NewNotificationMessage creates a new message containing one notification body with values obtained from the input parameter
func NewNotificationMessage(tok token.Token, t section.NotificationType, data string) message.Message {
	msg, _ := NewNotificationsMessage([]token.Token{tok}, []section.NotificationType{t}, []string{data})
	return msg
}

//SendQuery creates a connection with connInfo, frames msg and writes it to the connection.
//It then waits for the response. When it receives the response or times out, it returns the answer
//or an error.
func SendQuery(msg message.Message, addr net.Addr, timeout time.Duration) (
	message.Message, error) {

	conn, err := connection.CreateConnection(addr)
	fmt.Printf("SendQuery: %T, %T\n", addr, conn)
	if err != nil {
		return message.Message{}, err
	}
	defer conn.Close()

	done := make(chan message.Message)
	ec := make(chan error)
	go connection.ReceiveMessage(conn, msg.Token, done, ec)

	// Note: buffer message as direct Write to the Conn would be wrong for
	// datagram connections and potentially slow for stream connections
	encoding := new(bytes.Buffer)
	if err := cbor.NewWriter(encoding).Marshal(&msg); err != nil {
		return message.Message{}, fmt.Errorf("failed to marshal message to conn: %v", err)
	}
	if _, err := conn.Write(encoding.Bytes()); err != nil {
		return message.Message{}, fmt.Errorf("unable to write encoded message to connection: %v", err)
	}

	select {
	case msg := <-done:
		return msg, nil
	case err := <-ec:
		return message.Message{}, err
	case <-time.After(timeout):
		return message.Message{}, fmt.Errorf("timed out waiting for response")
	}
}

// GetOverlapValidityForSignatures returns the union of the validity windows for all signatures
// Returns 0,0 if no valid window exists (there exist gaps)
func GetOverlapValidityForSignatures(sigs []signature.Sig) (int64, int64) {
	// strategy is to sort the intervals using ValidSince and check the max validUntil for all of them
	if len(sigs) == 0 {
		return 0, 0
	}
	bySince := make([]*signature.Sig, len(sigs))
	for i := range sigs {
		bySince[i] = &sigs[i]
	}
	sort.Slice(bySince, func(i, j int) bool { return bySince[i].ValidSince < bySince[j].ValidSince })
	// now find out if there are gaps
	until := bySince[0].ValidUntil
	for i := 1; i < len(bySince); i++ {
		if until < bySince[i].ValidSince {
			return 0, 0
		}
		if bySince[i].ValidUntil > until {
			until = bySince[i].ValidUntil
		}
	}
	return bySince[0].ValidSince, until
}
