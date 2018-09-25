package utils

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"

	log "github.com/inconshreveable/log15"
)

// TraceServer implements a server which clients can send traces to.
type TraceServer struct {
	sock       net.Listener
	m          *sync.Mutex
	traces     map[string]map[string][]string
	cachedJSON []byte // A cached copy of the above map as a JSON byte array.
	cacheValid bool
}

// NewTraceServer creates a TraceServer starts listening and launches a goroutine
// to handle requests.
func NewTraceServer(addr string) (*TraceServer, error) {
	c, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on socket: %v", err)
	}
	ts := &TraceServer{
		sock:   c,
		m:      &sync.Mutex{},
		traces: make(map[string]map[string][]string),
	}
	go ts.HandleClients()
	return ts, nil
}

// Traces returns the JSON formatted trace logs.
func (ts *TraceServer) Traces() []byte {
	ts.m.Lock()
	defer ts.m.Unlock()
	if !ts.cacheValid {
		enc, err := json.Marshal(ts.traces)
		if err != nil {
			log.Warn(fmt.Sprintf("failed to marshal traces: %v", err))
			enc = []byte(fmt.Sprintf("failed to marshal traces: %v", err))
		}
		ts.cachedJSON = enc
		ts.cacheValid = true
	}
	return ts.cachedJSON
}

// HandleClients handles clients of this TraceServer.
func (ts *TraceServer) HandleClients() {
	for {
		client, err := ts.sock.Accept()
		if err != nil {
			log.Warn(fmt.Sprintf("failed to accept connection from client: %v", err))
			continue
		}
		go ts.HandleClient(client)
	}
}

// HandleClient handles the handshake with and incoming messages from a specific client connection.
func (ts *TraceServer) HandleClient(conn net.Conn) {
	// Complete the handshake with the client.
	decoder := json.NewDecoder(conn)
	var hello map[string]string
	if err := decoder.Decode(&hello); err != nil {
		log.Warn(fmt.Sprintf("handshake with client %v failed, could not decode message: %v", conn.RemoteAddr(), err))
		conn.Close()
		return
	}
	if action, ok := hello["action"]; !ok || action != "hello" {
		log.Warn(fmt.Sprintf("invalid handshake from client: %v", conn.RemoteAddr()))
		conn.Close()
		return
	}
	serverID, ok := hello["serverID"]
	if !ok {
		log.Warn(fmt.Sprintf("no serverID specified from client: %v", conn.RemoteAddr()))
		conn.Close()
		return
	}
	ts.m.Lock()
	ts.traces[serverID] = make(map[string][]string)
	serverMap := ts.traces[serverID]
	ts.m.Unlock()
	resp := map[string]string{
		"status": "ok",
	}
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(resp); err != nil {
		log.Warn(fmt.Sprintf("failed to respond to client %q handshake: %v", conn.RemoteAddr(), err))
		conn.Close()
		return
	}
	for {
		var req map[string]string
		if err := decoder.Decode(&req); err != nil {
			log.Warn(fmt.Sprintf("failed to decode message from client %q: %v", conn.RemoteAddr(), err))
			conn.Close()
			return
		}
		token, ok := req["token"]
		if !ok {
			log.Warn(fmt.Sprintf("missing token from client: %v", conn.RemoteAddr()))
			continue
		}
		message, ok := req["message"]
		if !ok {
			log.Warn(fmt.Sprintf("missing message from client: %v", conn.RemoteAddr()))
			continue
		}
		ts.m.Lock()
		serverMap[token] = append(serverMap[token], message)
		ts.cacheValid = false
		ts.m.Unlock()
	}
}
