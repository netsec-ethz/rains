# Connections and Capabilities

## Cache design decisions
- Servers keep long lived TLS over TCP connections with each other to reduce connection creation and
  teardown overhead. Thus it is essential to have a fast lookup of a connection and if there is none
  to establish a new one.
- Servers exchange their capabilities after establishing a connection. The capabilities
  of a server are stored in the same cache entry as the connection with it. The reasons for that are:
  - For a server to change its capabilities it must be restarted. As a result all connections are 
    torn down and after the restart every other server again connecting to it directly gets the new 
    capability list.
  - Due to long lived connections the overhead of exchanging capabilities is minimal.
  - There are no issues when Rains servers are behind load balancers (in contrast to the case where
    capabilities are bound to an IP. There it could happen that the IP is the same for 
    multiple servers with possibly different capabilities).
- A server can either send a list of capabilities or a hash thereof. Thus, a server should also
  cache a mapping of a capability hash to a pointer to a list of capabilities such that it
  does not have to request the whole list over and over again for common hashes.
- A pointer to a whole capability list is stored together with each connection such that even when 
  a hash to capability mapping is removed from the cache, it is still clear what the capabilities
  are. We store a pointer to reduce storage overhead.

## capability cache requirements
- cache has a fixed size which is configurable (to avoid memory exhaustion of the server in case of
  an attack).
- the least recently used hash to capability mapping must be removed from the cache when it is full.
- it must provide an insertion function.
- it must provide fast lookup of a pointer to a capability list based on the hash of the capability
  list
- all cache operations must be safe for concurrent access

## zone key cache implementation
- lru strategy is implemented as a linked list where pointers to the head and tail of the list are
  accessible.
- on insertion or lookup of a key it is moved to the head of the list
- in case the cache is full the entry at the tail of the list is removed.
- to allow fast lookup a hash map is used. It is keyed by the hash of the capability list. The value
  is a pointer to the corresponding list node.
- a list node contains a pointer to a capability list.

## connection cache requirements
- cache has a fixed size which is configurable (to avoid memory exhaustion of the server in case of
  an attack).
- a cache entry is either removed because it is the least recently used in case the cache is full or
  the connection was closed. 
- it must provide an insertion function.
- it must provide fast lookup to connections and pointers to capability lists based on the
  connection's type and addr. If there are several connections stored, it returns all of them.
- it must provide a mechanism to detect and delete closed connections.
- it must also provide a delete method which closes the connection and deletes the entry based on the
  connection's type and address (in case a server actively wants to terminate a connection).
- all cache operations must be safe for concurrent access

## connection cache implementation
- lru strategy is implemented as a linked list where pointers to the head and tail of the list are
  accessible.
- on insertion or lookup of a key it is moved to the head of the list
- in case the cache is full the entry at the tail of the list is removed.
- to allow fast lookup a hash map is used. It is keyed by the connection's type and address. The
  value is a pointer to the corresponding list node.
- a list node contains a list of objects which consists of a pointer to a capability list and a 
  connection object.
