package main

import (
	"bytes"

	"github.com/britram/borat"
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/message"
)

func main() {
	/*keycreator.DelegationAssertion(".", ".", "keys/selfSignedRootDelegationAssertion.gob", "keys/rootPrivateKey.txt")
	conf, _ := rainsd.LoadConfig("config/server.conf")
	server, err := rainsd.New(conf, "0")
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
	log.Info("Server shut down")*/
}

func handleResponse(channel chan connection.Message) {
	data := <-channel
	//log.Error(data.Sender.RemoteAddr().String(), "", data.Msg)
	msg := &message.Message{}
	msg.UnmarshalCBOR(borat.NewCBORReader(bytes.NewReader(data.Msg)))
	log.Info("", "", msg)
}
