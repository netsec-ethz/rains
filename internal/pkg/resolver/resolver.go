package resolver

import (
	"bytes"
	"fmt"

	log "github.com/inconshreveable/log15"

	"github.com/britram/borat"
	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

type Server struct {
	input           *connection.Channel
	cachingResolver func(connection.Message)
	rootIPAddr      string
	ipToChan        map[string]func(connection.Message)
	newTokenToMsg   map[token.Token]*message.Message
}

func New(id string, cachingResolver func(connection.Message), rootIPAddr string, ipToChan map[string]func(connection.Message)) *Server {
	server := &Server{
		input:           &connection.Channel{RemoteChan: make(chan connection.Message, 100)},
		cachingResolver: cachingResolver,
		rootIPAddr:      rootIPAddr,
		ipToChan:        ipToChan,
		newTokenToMsg:   make(map[token.Token]*message.Message),
	}
	server.input.SetRemoteAddr(connection.ChannelAddr{ID: id})
	return server
}

func (s *Server) Start() {
	log.Error("Starting recursive resolver", "ID", s.input.RemoteAddr().String())
	for {
		msg := <-s.input.RemoteChan
		m := &message.Message{}
		reader := cbor.NewReader(bytes.NewBuffer(msg.Msg))
		if err := reader.Unmarshal(m); err != nil {
			log.Warn(fmt.Sprintf("failed to unmarshal msg recv over channel: %v", err))
			continue
		}
		if "-"+msg.Sender.RemoteAddr().String() == s.input.RemoteAddr().String() {
			//New query from the caching resolver
			log.Error("RR received message from caching resolver", "resolver", msg.Sender.RemoteAddr().String(), "msg", m)
			newToken := forwardQuery(*m, s.input, s.ipToChan[s.rootIPAddr], s.rootIPAddr)
			s.newTokenToMsg[newToken] = m
		} else {
			//New answer from a recursive lookup
			//FIXME does not work with self reference in subjectName (@)
			log.Error("RR received message from a naming server", "namingServer", msg.Sender.RemoteAddr().String(), "msg", m)
			oldMsg := s.newTokenToMsg[m.Token]
			switch sec := m.Content[0].(type) {
			case *section.Assertion:
				if oldMsg.Query().Name == sec.FQDN() {
					returnToCachingResolver(oldMsg.Token, *m, s.input, s.cachingResolver)
				} else {
					//FIXME CFE assumes that the response of a naming server contains 4 assertions
					//where the last one is of ip4 type
					addr := m.Content[3].(*section.Assertion).Content[0].Value.(string)
					newToken := forwardQuery(*m, s.input, s.ipToChan[addr], addr)
					delete(s.newTokenToMsg, m.Token)
					s.newTokenToMsg[newToken] = oldMsg
				}
			case *section.Shard, *section.Zone:
				returnToCachingResolver(oldMsg.Token, *m, s.input, s.cachingResolver)
			}
		}
	}
}

//Write delivers an encoded rains message and a response inputChannel to the server.
func (s *Server) Write(msg connection.Message) {
	s.input.RemoteChan <- msg
}

func forwardQuery(msg message.Message, input *connection.Channel, forward func(connection.Message), addr string) token.Token {
	msg.Token = token.New()
	encoding := new(bytes.Buffer)
	err := msg.MarshalCBOR(borat.NewCBORWriter(encoding))
	panicOnError(err)
	forward(connection.Message{Msg: encoding.Bytes(), Sender: input})
	log.Error("RR sent message to naming server", "namingServer", addr, "msg", msg)
	return msg.Token
}

func returnToCachingResolver(oldToken token.Token, msg message.Message, input *connection.Channel, output func(connection.Message)) {
	msg.Token = oldToken
	encoding := new(bytes.Buffer)
	err := msg.MarshalCBOR(borat.NewCBORWriter(encoding))
	panicOnError(err)
	output(connection.Message{Msg: encoding.Bytes(), Sender: input})
	log.Error("RR sent message back to caching resolver", "msg", msg)
}

func panicOnError(err error) {
	if err != nil {
		panic(err.Error())
	}
}
