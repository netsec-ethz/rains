package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// TraceWeb implements a web server to view the trace data collected.
type TraceWeb struct {
	ts *TraceServer
}

// NewTraceWeb creates a new TraceWeb instance given a TraceServer.
func NewTraceWeb(ts *TraceServer) *TraceWeb {
	return &TraceWeb{
		ts: ts,
	}
}

// TraceHandler returns the JSON encoded traces to a web client.
func (tw *TraceWeb) TraceHandler(r http.ResponseWriter, req *http.Request) {
	r.Header().Add("Content-Type", "application/json")
	r.Write(tw.ts.Traces())
}

func (tw *TraceWeb) TraceHuman(r http.ResponseWriter, req *http.Request) {
	r.Header().Add("Content-Type", "application/json")
	var m map[string]map[string][]string
	if err := json.Unmarshal(tw.ts.Traces(), &m); err != nil {
		r.WriteHeader(500)
		r.Write([]byte(fmt.Sprintf("failed to unmarshal json: %v", err)))
		return
	}
}

// ListenAndServe configures the routes and starts the HTTP server.
func (tw *TraceWeb) ListenAndServe(addr string) error {
	http.HandleFunc("/traces", tw.TraceHandler)
	return http.ListenAndServe(addr, nil)
}
