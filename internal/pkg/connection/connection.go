package connection

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"

	sd "github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
)

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
	case "Chan":
		value = reflect.New(reflect.TypeOf(ChannelAddr{})).Interface()
		t = Chan
		addrData, err := json.Marshal(m["Addr"])
		if err != nil {
			return -1, nil, err
		}
		if err = json.Unmarshal(addrData, &value); err != nil {
			return -1, nil, err
		}
	case "SCION":
		if _, ok := m["Local"]; !ok {
			return -1, nil, errors.New("local address is required for SCION")
		}
		local, ok := m["Local"].(string)
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
	Chan Type = iota
	TCP
	SCION
)

type Message struct {
	Sender *Channel
	Msg    []byte
}

type ChannelAddr struct {
	ID string
}

//Network returns channel
func (c ChannelAddr) Network() string {
	return "channel"
}

//String returns the channel's id
func (c ChannelAddr) String() string {
	return c.ID
}

type Channel struct {
	localAddr  ChannelAddr
	LocalChan  chan Message
	remoteAddr ChannelAddr
	RemoteChan chan Message
}

func (c *Channel) Read(b []byte) (n int, err error) {
	msg := <-c.LocalChan
	c.localAddr = msg.Sender.RemoteAddr().(ChannelAddr)
	c.LocalChan = msg.Sender.RemoteChan
	return len(b), nil
}

func (c *Channel) Write(b []byte) (n int, err error) {
	c.RemoteChan <- Message{
		Msg: b,
		Sender: &Channel{
			remoteAddr: c.LocalAddr().(ChannelAddr),
			RemoteChan: c.LocalChan,
		},
	}
	return len(b), nil
}

func (c *Channel) Close() error {
	return nil
}
func (c *Channel) LocalAddr() net.Addr {
	return c.localAddr
}
func (c *Channel) SetLocalAddr(addr ChannelAddr) {
	c.localAddr = addr
}
func (c *Channel) RemoteAddr() net.Addr {
	return c.remoteAddr
}
func (c *Channel) SetRemoteAddr(addr ChannelAddr) {
	c.remoteAddr = addr
}
func (c *Channel) SetDeadline(t time.Time) error {
	return nil
}
func (c *Channel) SetReadDeadline(t time.Time) error {
	return nil
}
func (c *Channel) SetWriteDeadline(t time.Time) error {
	return nil
}

//CreateConnection returns a newly created connection with connInfo or an error
func CreateConnection(addr net.Addr) (conn net.Conn, err error) {
	switch addr.(type) {
	case *net.TCPAddr:
		return tls.Dial(addr.Network(), addr.String(), &tls.Config{InsecureSkipVerify: true})
	case *snet.Addr:
		return nil, errors.New("creating SCION connections is unsupported")
	default:
		return nil, errors.New("unsupported Network address type")
	}
}

// choosePathSCION is a naive implementation of a path selection algorithm that
// chooses the first available path.
func choosePathSCION(ctx context.Context, la, ra *snet.Addr) *sd.PathReplyEntry {
	pathMgr := snet.DefNetwork.PathResolver()
<<<<<<< HEAD
	pathSet := pathMgr.Query(ctx, la.IA, ra.IA, sd.PathReqFlags{})
=======
	pathSet := pathMgr.Query(ctx, la.IA, ra.IA)
	//pathSet := pathMgr.Query(ctx, la.IA, ra.IA)
>>>>>>> f13f222386b002869601447a6ab7797434187979
	for _, p := range pathSet {
		return p.Entry
	}
	return nil
}

func Listen(conn net.Conn, tok token.Token, done chan<- message.Message, ec chan<- error) {
	reader := cbor.NewReader(conn)
	var msg message.Message
	if err := reader.Unmarshal(&msg); err != nil {
		if err.Error() == "failed to read tag: EOF" {
			ec <- fmt.Errorf("connection has been closed")
		} else {
			ec <- fmt.Errorf("failed to unmarshal response: %v", err)
		}
		return
	}
	if msg.Token != tok {
		if n, ok := msg.Content[0].(*section.Notification); !ok || n.Token != tok {
			ec <- fmt.Errorf("token response mismatch: got %v, want %v", msg.Token, tok)
			return
		}
	}
	done <- msg
}
