package resolver

import (
	"bytes"
	"fmt"
	"time"

	"github.com/britram/borat"
	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/internal/pkg/cbor"
	"github.com/netsec-ethz/rains/internal/pkg/connection"
	"github.com/netsec-ethz/rains/internal/pkg/generate"
	"github.com/netsec-ethz/rains/internal/pkg/message"
	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/section"
	"github.com/netsec-ethz/rains/internal/pkg/token"
)

type Server struct {
	input           *connection.Channel
	cachingResolver func(connection.Message)
	rootIPAddr      string
	ipToChan        map[string]func(connection.Message)
	newTokenToMsg   map[token.Token]*message.Message
	delegations     map[string]*section.Assertion
	continent       int
	tld             int
	delay           *generate.Delay
}

func New(id string, cachingResolver func(connection.Message), rootIPAddr string,
	ipToChan map[string]func(connection.Message), continent, tld int, delay *generate.Delay) *Server {
	server := &Server{
		input:           &connection.Channel{RemoteChan: make(chan connection.Message, 100)},
		cachingResolver: cachingResolver,
		rootIPAddr:      rootIPAddr,
		ipToChan:        ipToChan,
		newTokenToMsg:   make(map[token.Token]*message.Message),
		delegations:     make(map[string]*section.Assertion),
		continent:       continent,
		tld:             tld,
		delay:           delay,
	}
	server.input.SetRemoteAddr(connection.ChannelAddr{ID: id})
	return server
}

func (s *Server) Start() {
	log.Info("Starting recursive resolver", "ID", s.input.RemoteAddr().String())
	for {
		msg := <-s.input.RemoteChan
		m := &message.Message{}
		reader := cbor.NewReader(bytes.NewBuffer(msg.Msg))
		if err := reader.Unmarshal(m); err != nil {
			log.Warn(fmt.Sprintf("failed to unmarshal msg recv over channel: %v", err))
			continue
		}
		//if "-"+msg.Sender.RemoteAddr().String() == s.input.RemoteAddr().String() { FIXME CFE
		//RemoteAddr is not correctly returned by naming server. Why?
		if oldMsg, ok := s.newTokenToMsg[m.Token]; !ok {
			//New query from the caching resolver
			log.Info("RR received message from caching resolver", "resolver", msg.Sender.RemoteAddr().String(), "msg", m)
			q := m.Query()
			if q.Types[0] == object.OTDelegation {
				if a, ok := s.delegations[q.Name]; ok {
					m.Content = []section.Section{a}
					returnToCachingResolver(m.Token, *m, s.input, s.cachingResolver)
					continue
				}
			}
			newToken := forwardQuery(*m, s.input, s.ipToChan[s.rootIPAddr], s.rootIPAddr, s.continent, s.tld, s.delay)
			s.newTokenToMsg[newToken] = m
		} else {
			//New answer from a recursive lookup
			//FIXME does not work with self reference in subjectName (@)
			log.Info("RR received message from a naming server", "namingServer", msg.Sender.RemoteAddr().String(), "msg", m)
			//oldMsg := s.newTokenToMsg[m.Token] //FIXME CFE see above
			switch sec := m.Content[0].(type) {
			case *section.Assertion:
				if sec.Content[0].Type == object.OTDelegation {
					s.delegations[sec.FQDN()] = sec
				}
				if oldMsg.Query().Name == sec.FQDN() {
					returnToCachingResolver(oldMsg.Token, *m, s.input, s.cachingResolver)
				} else {
					//FIXME CFE assumes that the response of a naming server contains 4 assertions
					//where the last one is of ip4 type
					addr := m.Content[3].(*section.Assertion).Content[0].Value.(string)
					newToken := forwardQuery(*oldMsg, s.input, s.ipToChan[addr], addr, s.continent, s.tld, s.delay)
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

func forwardQuery(msg message.Message, input *connection.Channel, forward func(connection.Message),
	addr string, continent, tld int, delay *generate.Delay) token.Token {
	msg.Token = token.New()
	encoding := new(bytes.Buffer)
	err := msg.MarshalCBOR(borat.NewCBORWriter(encoding))
	panicOnError(err)
	//TODO CFE instead of adding all the delay when sending, add half of it when it is received
	log.Info("RTT to naming server", "Delay", delay.Calc(continent, tld, addr))
	time.Sleep(delay.Calc(continent, tld, addr))
	forward(connection.Message{Msg: encoding.Bytes(), Sender: input})
	log.Info("RR sent message to naming server", "namingServer", addr, "msg", msg)
	return msg.Token
}

func returnToCachingResolver(oldToken token.Token, msg message.Message, input *connection.Channel, output func(connection.Message)) {
	msg.Token = oldToken
	encoding := new(bytes.Buffer)
	err := msg.MarshalCBOR(borat.NewCBORWriter(encoding))
	panicOnError(err)
	output(connection.Message{Msg: encoding.Bytes(), Sender: input})
	log.Info("RR sent message back to caching resolver", "msg", msg)
}

func panicOnError(err error) {
	if err != nil {
		panic(err.Error())
	}
}
