package resolver

import (
	"bytes"
	"fmt"
	"strconv"

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
	cachingResolver *connection.Channel
	rootIPAddr      string
	ipToChan        map[string]*connection.Channel
	newTokenToMsg   map[token.Token]*message.Message
}

func New(id int, cachingResolver *connection.Channel, rootIPAddr string, ipToChan map[string]*connection.Channel) *Server {
	server := &Server{
		input:           &connection.Channel{RemoteChan: make(chan connection.Message, 100)},
		cachingResolver: cachingResolver,
		rootIPAddr:      rootIPAddr,
		ipToChan:        ipToChan,
		newTokenToMsg:   make(map[token.Token]*message.Message),
	}
	server.input.SetRemoteAddr(connection.ChannelAddr{ID: strconv.Itoa(id)})
	return server
}

func (s *Server) Start() {
	for {
		msg := <-s.input.RemoteChan
		m := &message.Message{}
		reader := cbor.NewReader(bytes.NewBuffer(msg.Msg))
		if err := reader.Unmarshal(m); err != nil {
			log.Warn(fmt.Sprintf("failed to unmarshal msg recv over channel: %v", err))
			continue
		}
		if msg.Sender.RemoteAddr().String() == s.cachingResolver.RemoteAddr().String() {
			//New query from the caching resolver
			newToken := forwardQuery(*m, s.input, s.ipToChan[s.rootIPAddr])
			s.newTokenToMsg[newToken] = m
		} else {
			//New answer from a recursive lookup
			//FIXME does not work with self reference in subjectName (@)
			oldMsg := s.newTokenToMsg[m.Token]
			switch sec := m.Content[0].(type) {
			case *section.Assertion:
				if oldMsg.Query().Name == fmt.Sprintf("%s.%s", sec.SubjectName, sec.SubjectZone) {
					returnToCachingResolver(oldMsg.Token, *m, s.input, s.cachingResolver)
				} else {
					//FIXME CFE assumes that the response of a naming server contains 4 assertions
					//where the last one is of ip4 type
					newToken := forwardQuery(*m, s.input, s.ipToChan[m.Content[3].(*section.Assertion).Content[0].Value.(string)])
					delete(s.newTokenToMsg, m.Token)
					s.newTokenToMsg[newToken] = oldMsg
				}
			case *section.Shard, *section.Zone:
				returnToCachingResolver(oldMsg.Token, *m, s.input, s.cachingResolver)
			}
		}
	}
}

func forwardQuery(msg message.Message, input, forward *connection.Channel) token.Token {
	msg.Token = token.New()
	encoding := new(bytes.Buffer)
	err := msg.MarshalCBOR(borat.NewCBORWriter(encoding))
	panicOnError(err)
	forward.RemoteChan <- connection.Message{Msg: encoding.Bytes(), Sender: input}
	return msg.Token
}

func returnToCachingResolver(oldToken token.Token, msg message.Message, input, output *connection.Channel) {
	msg.Token = oldToken
	encoding := new(bytes.Buffer)
	err := msg.MarshalCBOR(borat.NewCBORWriter(encoding))
	panicOnError(err)
	output.RemoteChan <- connection.Message{Msg: encoding.Bytes(), Sender: input}
}

func panicOnError(err error) {
	if err != nil {
		panic(err.Error())
	}
}
