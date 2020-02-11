package connection

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"

	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/connection/scion"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/scionproto/scion/go/lib/snet"
)

const MaxUDPPacketBytes = 9000

//Info contains address information about one actor of a connection of the declared type
type Info struct {
	Type Type
	Addr net.Addr
}

// UnmarshalJSON implements the JSONUnmarshaler interface.
func (c *Info) UnmarshalJSON(data []byte) error {
	var err error
	c.Type, c.Addr, err = UnmarshalNetAddr(data)
	if err != nil {
		return err
	}
	return nil
}

// UnmarshalNetAddr is a helper function that unmarshals network addresses.
func UnmarshalNetAddr(data []byte) (Type, net.Addr, error) {
	m := map[string]interface{}{}
	if err := json.Unmarshal(data, &m); err != nil {
		return -1, nil, err
	}
	var t Type
	var value interface{}
	switch m["Type"].(string) {
	case "TCP":
		value = reflect.New(reflect.TypeOf(net.TCPAddr{})).Interface()
		t = TCP
		if _, ok := m["TCPAddr"]; !ok {
			return -1, nil, errors.New("TCPAddr key not found in JSON config")
		}
		addrData, err := json.Marshal(m["TCPAddr"])
		if err != nil {
			return -1, nil, err
		}
		if err = json.Unmarshal(addrData, &value); err != nil {
			return -1, nil, err
		}
	case "SCION":
		if _, ok := m["SCIONAddr"]; !ok {
			return -1, nil, errors.New("local address is required for SCION")
		}
		local, ok := m["SCIONAddr"].(string)
		if !ok {
			return -1, nil, errors.New("local address must be a string")
		}
		scionLocal, err := snet.UDPAddrFromString(local)
		if err != nil {
			return -1, nil, fmt.Errorf("failed to parse local addr: %v", err)
		}
		if scionLocal == nil {
			return -1, nil, fmt.Errorf("returned SCION address was nil")
		}
		value = scionLocal
		t = SCION
	default:
		return -1, nil, errors.New("Unknown Addr type")
	}
	return t, value.(net.Addr), nil
}

//Type enumerates connection types
type Type int

//run 'go generate' in this directory if a new networkAddrType is added [source https://github.com/campoy/jsonenums]
//go:generate jsonenums -type=Type
//go:generate stringer -type=Type
const (
	TCP Type = iota + 1
	SCION
)

//CreateConnection returns a newly created connection with connInfo or an error
func CreateConnection(addr net.Addr) (conn net.Conn, err error) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return tls.Dial(a.Network(), a.String(), &tls.Config{InsecureSkipVerify: true})
	case *snet.UDPAddr:
		return scion.DialAddr(a)
	default:
		return nil, fmt.Errorf("unsupported Network address type: %s", addr)
	}
}

func ReceiveMessageAsync(conn net.Conn, tok token.Token, done chan<- message.Message, ec chan<- error) {
	msg, err := ReceiveMessage(conn)
	if err != nil {
		ec <- err
		return
	}
	// XXX(matzf): this gives up after one wrong message? Why not _at least_ retry until timeout?!
	if msg.Token != tok {
		if n, ok := msg.Content[0].(*section.Notification); !ok || n.Token != tok {
			ec <- fmt.Errorf("token response mismatch: got %v, want %v", msg.Token, tok)
			return
		}
	}
	done <- *msg
}

// ReceiveMessage receives and unmarshals one message.Message from conn.
// conn can either be a datagram (PacketConn) or a stream connection.
func ReceiveMessage(conn net.Conn) (*message.Message, error) {
	var reader io.Reader
	switch c := conn.(type) {
	case net.PacketConn:
		// XXX(matzf): this is a weird check because it requires the conn to be
		// Conn and PacketConn, but this works for snet.Conn and net.UDPConn.

		// Read one datagram and then parse message from buffer
		buf := make([]byte, MaxUDPPacketBytes)
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return nil, fmt.Errorf("Failed to Read: %v", err)
		}
		reader = bytes.NewReader(buf[:n])
	default:
		reader = conn
	}

	msg := new(message.Message)
	if err := cbor.NewReader(reader).Unmarshal(msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CBOR: %v", err)
	}
	return msg, nil
}

// WriteMessage marshals one message.Message and writes it to conn.
// conn can either be a datagram (PacketConn) or a stream connection.
func WriteMessage(conn net.Conn, msg *message.Message) error {

	// Note: buffer message as direct Write to the Conn would be wrong for
	// datagram connections and potentially slow for stream connections
	encoding := new(bytes.Buffer)
	if err := cbor.NewWriter(encoding).Marshal(msg); err != nil {
		return fmt.Errorf("failed to marshal message: %s", err)
	}
	if _, err := conn.Write(encoding.Bytes()); err != nil {
		return fmt.Errorf("unable to write encoded message to connection: %s", err)
	}
	return nil
}
