package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// TestTracker is used to report progress and track results of the tests.
type TestTracker struct {
	Cont         chan struct{}
	RainsdConfs  map[string]string
	ZoneFiles    map[string]string
	VerifyOutput map[string]string
}

// TraceWeb implements a web server to view the trace data collected.
type TraceWeb struct {
	ts *TraceServer
	tt *TestTracker
}

// NewTraceWeb creates a new TraceWeb instance given a TraceServer.
func NewTraceWeb(ts *TraceServer, tt *TestTracker) *TraceWeb {
	return &TraceWeb{
		ts: ts,
		tt: tt,
	}
}

// TraceHandler returns the JSON encoded traces to a web client.
func (tw *TraceWeb) TraceHandler(r http.ResponseWriter, req *http.Request) {
	r.Header().Add("Content-Type", "application/json")
	r.Write(tw.ts.Traces())
}

func (tw *TraceWeb) Cont(r http.ResponseWriter, req *http.Request) {
	tw.tt.Cont <- struct{}{}
	r.WriteHeader(201)
}

func (tw *TraceWeb) RainsdConfs(r http.ResponseWriter, req *http.Request) {
	r.Header().Add("Content-Type", "application/json")
	enc := json.NewEncoder(r)
	if err := enc.Encode(tw.tt.RainsdConfs); err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal: %v", err)
		r.WriteHeader(500)
	}
}

func (tw *TraceWeb) ZoneFiles(r http.ResponseWriter, req *http.Request) {
	r.Header().Add("Content-Type", "application/json")
	enc := json.NewEncoder(r)
	if err := enc.Encode(tw.tt.ZoneFiles); err != nil {
		fmt.Fprintf(os.Stderr, "failed to marhsal: %v", err)
		r.WriteHeader(500)
	}
}

func (tw *TraceWeb) VerifyOutput(r http.ResponseWriter, req *http.Request) {
	r.Header().Add("Content-Type", "application/json")
	enc := json.NewEncoder(r)
	if err := enc.Encode(tw.tt.VerifyOutput); err != nil {
		fmt.Fprintf(os.Stderr, "failed to marhsal: %v", err)
		r.WriteHeader(500)
	}
}

// ListenAndServe configures the routes and starts the HTTP server.
func (tw *TraceWeb) ListenAndServe(addr string) error {
	http.HandleFunc("/traces", tw.TraceHandler)
	http.HandleFunc("/cont", tw.Cont)
	http.HandleFunc("/RainsdConfs", tw.RainsdConfs)
	http.HandleFunc("/ZoneFiles", tw.ZoneFiles)
	http.HandleFunc("/VerifyOutput", tw.VerifyOutput)
	http.Handle("/", http.FileServer(http.Dir("integration/web")))
	return http.ListenAndServe(addr, nil)
}
