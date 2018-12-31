# RAINS server design

This document describes the implementation design of a RAINS servers and how it processes Queries
and Assertions depending on its configuration. A RAINS server consists of four modules which process
Queries and Assertions sequentially, a resolver which performs recursive lookups, six caches which
allow quick access to stored information, and three queues where incoming messages are places in
case of congestion.

## Modules

### Switchboard

The switchboard is responsible for handling all network connections. It is capable to listen on all
supported transport protocols and send RAINS messages on top of them. Currently, the switchboard
supports TLS-over-TCP, scion-UDP, and go channels as a transport. 

The switchboard acts on the following event as follows:
- Connection request from another server/client: If the source of the request is not blacklisted,
  the connection is accepted and a new go routine is created which listens for incoming messages.
- Incoming message on a connection: The cbor encoded message is decoded into a message object and
  passed to the inbox module.
- Send request to a network addr: If there is not an active connection with the destination, a new
  connection is opened. Then the message is cbor encoded and sent to the destination. If an error
  occurs, it retries the send the message for the specified amount of times. 
- Request for a recursive lookup: The message is forwarded to the configured recursive resolver.

### Inbox

The inbox is responsible for handling capabilities, prioritizing messages, and queuing the incoming
messages or assigning them to workers. The inbox first processes capabilities and takes appropriate
actions. It then splits the messages content into three groups - Notifications, Queries, and
Assertions - which are handled separately. Assertions which are an answer to a delegation query
issued by this server are handled with priority. All three groups are put onto dedicated queues from
which the worker go routines start processing the different parts of the incoming messages. All
queries of a message are processed together. Also all Assertions of a message are processed
together. If a client wants several queries to be processed separately, he must send each query in a
separate message. 

### Verify

### Engine

## Recursive Resolver

### Recursive Lookup

## Caches

### Assertion Cache

### Zone Key Cache

### Negative Assertion Cache

### Connection/Capability Cache

### Pending Query Cache

### Pending Key Cache

## Queues

### Normal Queue

### Priority Queue

### Notification Queue

## Authoritative Server vs. Caching Resolver

## Processing a Query

## Processing an Assertion

## Concurrency 

