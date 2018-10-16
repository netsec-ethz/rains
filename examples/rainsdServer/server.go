package main

import (
	"bytes"
	"time"

	"github.com/britram/borat"
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/publisher"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/rainsd"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
	"github.com/netsec-ethz/rains/tools/keycreator"
)

func main() {
	keycreator.DelegationAssertion(".", ".")
	server, err := rainsd.New("config/server.conf", log.LvlDebug, "0")
	if err != nil {
		log.Error(err.Error())
		return
	}
	log.Info("Server successfully initialized")
	go server.Start(false)

	config, err := publisher.LoadConfig("config/publisher.conf")
	if err != nil {
		log.Error(err.Error())
		return
	}
	pubServer := publisher.New(config)
	pubServer.Publish()
	time.Sleep(time.Second)
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
	rcvChan := make(chan connection.Message)
	deliverable := connection.Message{
		Msg:    encoding.Bytes(),
		Sender: &connection.Channel{RemoteChan: rcvChan},
	}
	deliverable.Sender.SetRemoteAddr(connection.ChannelAddr{ID: "1"})
	go handleResponse(rcvChan)
	server.Write(deliverable)

	time.Sleep(time.Hour)
	server.Shutdown()
	log.Info("Server shut down")
}

func handleResponse(channel chan connection.Message) {
	data := <-channel
	log.Error(data.Sender.RemoteAddr().String(), "", data.Msg)
	msg := &message.Message{}
	msg.UnmarshalCBOR(borat.NewCBORReader(bytes.NewReader(data.Msg)))
	log.Error("", "", msg)
}
