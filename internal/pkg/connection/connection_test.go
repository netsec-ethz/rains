package connection

import (
	"bytes"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/britram/borat"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

func TestConnection(t *testing.T) {
	//FIXME this test returns always true, write a real test
	msg := message.Message{
		Capabilities: []message.Capability{message.NoCapability},
		Token:        token.New(),
		Content: []section.Section{
			&query.Name{
				Context:    ".",
				Name:       "ch.",
				Expiration: time.Now().Add(time.Second).Unix(),
				Types:      []object.Type{object.OTIP4Addr},
			},
		},
	}
	encoding := new(bytes.Buffer)
	if err := msg.MarshalCBOR(borat.NewCBORWriter(encoding)); err != nil {
		log.Error(err.Error())
		return
	}
	rcvChan := make(chan Message, 1)
	/*deliverable := Message{
		Msg:    encoding.Bytes(),
		Sender: Channel{RemoteChan: rcvChan},
	}
	deliverable.Sender.SetRemoteAddr(connection.ChannelAddr{ID: "1"})*/

	serverConn := Channel{RemoteChan: rcvChan, LocalChan: make(chan Message, 1)}
	serverConn.SetRemoteAddr(ChannelAddr{"1"})
	serverConn.SetLocalAddr(ChannelAddr{"0"})
	serverConn.Write(encoding.Bytes())
	rcvMsg := <-rcvChan
	log.Error("", "", rcvMsg, "", *rcvMsg.Sender)
}
