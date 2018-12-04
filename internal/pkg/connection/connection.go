package connection

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

//Info contains address information about one actor of a connection of the declared type
type Info struct {
	//Type determines the network address type
	Type Type

	TCPAddr  *net.TCPAddr
	ChanAddr ChannelAddr
}

//String returns the string representation of the connection information according to its type
func (c Info) String() string {
	switch c.Type {
	case TCP:
		return c.TCPAddr.String()
	case Chan:
		return c.ChanAddr.String()
	default:
		log.Warn("Unsupported network address", "typeCode", c.Type)
		return ""
	}
}

//NetworkAndAddr returns the network name and addr of the connection separated by space
func (c Info) NetworkAndAddr() string {
	switch c.Type {
	case TCP:
		return fmt.Sprintf("%s %s", c.TCPAddr.Network(), c.String())
	case Chan:
		return fmt.Sprintf("%s %s", c.ChanAddr.Network(), c.String())
	default:
		log.Warn("Unsupported network address type", "type", c.Type)
		return ""
	}
}

//Hash returns a string containing all information uniquely identifying a Info.
func (c Info) Hash() string {
	return fmt.Sprintf("%v_%s", c.Type, c.String())
}

//Equal returns true if both Connection Information have the same existing type and the values corresponding to this type are identical.
func (c Info) Equal(conn Info) bool {
	if c.Type == conn.Type {
		switch c.Type {
		case TCP:
			return c.TCPAddr.IP.Equal(conn.TCPAddr.IP) && c.TCPAddr.Port == conn.TCPAddr.Port && c.TCPAddr.Zone == conn.TCPAddr.Zone
		default:
			log.Warn("Not supported network address type")
		}
	}
	return false
}

//Type enumerates connection types
type Type int

//run 'go generate' in this directory if a new networkAddrType is added [source https://github.com/campoy/jsonenums]
//go:generate jsonenums -type=Type
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
func CreateConnection(connInfo Info) (conn net.Conn, err error) {
	switch connInfo.Type {
	case TCP:
		return tls.Dial(connInfo.TCPAddr.Network(), connInfo.String(), &tls.Config{InsecureSkipVerify: true})
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
