package main

import (
	"log"
	"time"

	"github.com/netsec-ethz/rains/internal/pkg/object"
	"github.com/netsec-ethz/rains/internal/pkg/query"
	"github.com/netsec-ethz/rains/internal/pkg/section"
)

const nofZones = 1000000

func main() {
	var channels [nofZones]chan section.Section
	for i := range channels {
		channels[i] = make(chan section.Section)
		go worker(channels[i])
	}
	query := &query.Name{
		Name:       "example.com",
		Context:    ".",
		Types:      []object.Type{object.OTRegistrant},
		Expiration: 1000000,
	}
	start := time.Now()
	for _, c := range channels {
		c <- query
	}
	for _, c := range channels {
		<-c
	}
	elapsed := time.Since(start)
	log.Printf("Sending and receiving took %s", elapsed)
}

func worker(input chan section.Section) {
	a := &section.Assertion{
		SubjectName: "example",
		SubjectZone: "ch.",
		Context:     ".",
		Content:     []object.Object{object.Object{Type: object.OTRegistrant, Value: "Test registrant"}},
	}
	<-input
	//Simulates work on server side
	for i := 0; i < 1000; i++ {
		a.SubjectName = "Hello"
	}
	input <- a
}
