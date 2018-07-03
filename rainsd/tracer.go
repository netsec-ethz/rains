package rainsd

import (
	"encoding/json"
	"fmt"
	"net"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/rainslib"
)

// Tracer implements functionality to send metrics to the logging server.
type Tracer struct {
	serverID string
	remote   *net.Conn
	encoder  *json.Encoder
	queue    chan map[string]string
	shutdown chan struct{}
}

// SendMessage places a message in the buffer to be sent asynchronously.
func (t *Tracer) SendMessage(token rainslib.Token, message string) {
	m := make(map[string]string)
	m["serverID"] = t.serverID
	m["token"] = fmt.Sprintf("%v", token)
	m["message"] = message
	t.queue <- m
}

// SendLoop waits for and sends messages to the remote logging server.
func (t *Tracer) SendLoop() {
	for {
		select {
		case m := <-t.queue:
			if err := t.encoder.Encode(m); err != nil {
				log.Warn(fmt.Sprintf("failed to send message to remote: %v", err))
			}
		case <-t.shutdown:
			return
		}
	}
}

// NewTracer creates a new instance of a tracer and performs a handshake with the server.
// To use the tracer the client must run SendLoop() and then call SendMessage().
func NewTracer(serverID, addr string) (*Tracer, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to logging server: %v", err)
	}
	hello := map[string]string{
		"action":   "hello",
		"serverID": serverID,
	}
	enc := json.NewEncoder(c)
	enc.Encode(hello)
	dec := json.NewDecoder(c)
	var resp map[string]string
	if err := dec.Decode(&resp); err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to get response from server: %v", err)
	}
	if status, ok := resp["status"]; !ok {
		return nil, fmt.Errorf("response from server missing status key: %v", resp)
	} else if status != "ok" {
		return nil, fmt.Errorf("expected response status 'ok' but got %q", status)
	}
	return &Tracer{
		remote:   &c,
		serverID: serverID,
		encoder:  enc,
		queue:    make(chan map[string]string),
		shutdown: make(chan struct{}),
	}, nil
}
