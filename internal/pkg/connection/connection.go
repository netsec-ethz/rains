package connection

import (
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
)

//Info contains address information about one actor of a connection of the declared type
type Info struct {
	Type Type
	Addr net.Addr
}

func (c *Info) UnmarshalJSON(data []byte) error {
	var err error
	c.Type, c.Addr, err = UnmarshalNetAddr(data)
	if err != nil {
		return err
	}
	return nil
}

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
	case "Chan":
		value = reflect.New(reflect.TypeOf(ChannelAddr{})).Interface()
		t = TCP
	default:
		return -1, nil, errors.New("Unknown Addr type")
	}

	addrData, err := json.Marshal(m["Addr"])
	if err != nil {
		return -1, nil, err
	}
	if err = json.Unmarshal(addrData, &value); err != nil {
		return -1, nil, err
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
	default:
		return nil, errors.New("unsupported Network address type")
	}
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
