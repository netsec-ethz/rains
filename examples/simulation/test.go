package main

import (
	"log"
	"time"

	"github.com/netsec-ethz/rains/rainslib"
)

const nofZones = 1000000

func main() {
	var channels [nofZones]chan rainslib.MessageSection
	for i := range channels {
		channels[i] = make(chan rainslib.MessageSection)
		go worker(channels[i])
	}
	query := &rainslib.QuerySection{
		Name:       "example.com",
		Context:    ".",
		Types:      []rainslib.ObjectType{rainslib.OTRegistrant},
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

func worker(input chan rainslib.MessageSection) {
	a := &rainslib.AssertionSection{
		SubjectName: "example",
		SubjectZone: "ch.",
		Context:     ".",
		Content:     []rainslib.Object{rainslib.Object{Type: rainslib.OTRegistrant, Value: "Test registrant"}},
	}
	<-input
	//Simulates work on server side
	for i := 0; i < 1000; i++ {
		a.SubjectName = "Hello"
	}
	input <- a
}
