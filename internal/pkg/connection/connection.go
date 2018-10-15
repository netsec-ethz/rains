package connection

import (
	"fmt"
	"net"
	"time"

	log "github.com/inconshreveable/log15"
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
	case TCP, Chan:
		return fmt.Sprintf("%s %s", c.TCPAddr.Network(), c.String())
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
	Addr    ChannelAddr
	Channel chan Message
}

func (c *Channel) Read(b []byte) (n int, err error) {
	log.Warn("Don't use this method. Use ReadChannel instead")
	return len(b), nil
}
func (c *Channel) ReadChannel() Message {
	return <-c.Channel
}
func (c *Channel) Write(b []byte) (n int, err error) {
	log.Warn("Don't use this method. Use WriteChannel instead")
	return 0, nil
}
func (c *Channel) WriteChannel(msg Message) {
	c.Channel <- msg
}
func (c *Channel) Close() error {
	close(c.Channel)
	return nil
}
func (c *Channel) LocalAddr() net.Addr {
	return c.Addr
}
func (c *Channel) RemoteAddr() net.Addr {
	return c.Addr
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
