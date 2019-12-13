package connection

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"

	"bytes"

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
		scionLocal, err := snet.AddrFromString(local)
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
	switch addr.(type) {
	case *net.TCPAddr:
		return tls.Dial(addr.Network(), addr.String(), &tls.Config{InsecureSkipVerify: true})
	case *snet.Addr:
		return scion.Dial(addr.(*snet.Addr))
	default:
		return nil, fmt.Errorf("unsupported Network address type: %s", addr)
	}
}

func Listen(conn net.Conn, tok token.Token, done chan<- message.Message, ec chan<- error) {
	var msg message.Message
	switch conn.LocalAddr().(type) {
	case *net.TCPAddr:
		reader := cbor.NewReader(conn)
		if err := reader.Unmarshal(&msg); err != nil {
			if err.Error() == "failed to read tag: EOF" {
				ec <- fmt.Errorf("connection has been closed: %v", err)
			} else {
				ec <- fmt.Errorf("failed to unmarshal response: %v", err)
			}
			return
		}
	case *snet.Addr:
		buf := make([]byte, MaxUDPPacketBytes)
		n, _, err := conn.(snet.Conn).ReadFromSCION(buf)
		if err != nil {
			ec <- fmt.Errorf("Failed to ReadFromSCION: %v", err)
		}
		data := buf[:n]
		if err := cbor.NewReader(bytes.NewReader(data)).Unmarshal(&msg); err != nil {
			ec <- fmt.Errorf("failed to unmarshal CBOR: %v", err)
		}
	}
	if msg.Token != tok {
		if n, ok := msg.Content[0].(*section.Notification); !ok || n.Token != tok {
			ec <- fmt.Errorf("token response mismatch: got %v, want %v", msg.Token, tok)
			return
		}
	}
	done <- msg
}
