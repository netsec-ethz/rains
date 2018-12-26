# RAINS server design

This document describes the implementation design of a RAINS servers and how it processes Queries
and Assertions depending on its configuration. A RAINS server consists of four modules which process
Queries and Assertions sequentially, a resolver which performs recursive lookups, six caches which
allow quick access to stored information, and three queues where incoming messages are places in
case of congestion.

## Modules

### Switchboard

### Inbox

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

