# RAINS Project Plan

- Milestone 1: Implementation of a single RAINS server which is working and has all the basic functionality (without cryptography). 
  There are several test cases which ensure that the server works correctly.

- Task 1: Compare Design with Internet draft.
- Task 2: Implement `switchboard.go` where instead of another RAINS server `sendto()` sends a request to a DNS server until we have a partly working RAINS server.
          We maintain a list of open connections to other RAINS server. (We can determine that a query originated from a server by inspecting the capabilities. How?) 
          Make sure that these connections do not timeout by sending heartbeat Notification messages.
          Log successful and failed sends for later monitoring.
          Use a LRU strategy to drop connections if cache filled up (allow also for other strategies)
- Task 3: Write tests for `switchboard.go`.
- Task 4: Implement structure of `verify.go` (`verify()` just returns true, `delegate()` does nothing)
- Task 5: Implement `inbox.go`. There are three internal steps performed after each other.
    - call `verify()` to check the signature of the incoming package. Silently drop it if sig does not match.
    - Parse query options (Must happen before checking the expiration date, due to option Code 5 [ Expired assertions are acceptable ])
    - check the expiration date of the package and drop it or forward it by calling `assert() or query()` of the engine. (also pass along the parsed query options as a bit pattern?)    
          Use 2 queues for incoming messages based on the query token. 
    - Prio 1: Responses of self issued queries 
    - Prio 2: Incoming queries form clients or proactively pushed asserts/shards/zones by another RAINS server.
          Log if packets where successfully forwarded or if they are dropped. Monitor the dropped packets and take appropriate action if you see malicious attempts. 
          (e.g. a lot of expired packets from the same source -> possible DOS attack (Fill up Prio 2 queue) on the `verify()` step. Especially if they all need 
          different public keys -> The `verify()` step issues a lot of requests which then fill up the primary queue.)
- Task 6: Write tests for `inbox.go`.
- Task 7: Implement `engine.go`
    - `query()` different response depending if the request is internal or external, always check expiration time
    - `assert()` handles all queries awaiting this response and calls `cacheResult()` which returns if the result should be cached based on the configuration. Default: LRU
      Then it calls `checkConsistency()`, which updates the cache according to a configuration (see General remarks) 
      Log the different results
    - assertion cache
    - pending query cache
    - shard and zone storage. (used for non existence results) Quickly find the shard in which the assertions would be based on its range. (range map/interval tree)
- Task 8: Write tests for `engine.go`.
- Task 8: Implement `notification.go` which handles notification messages.
    - cache of capabilities of other servers. LRU strategy
- Task 10: Write tests for `notification.go`.


- Milestone 2: Implement a command line tool called rainsdig which enables you to interact with the RAINS server. It should be similar to dig for DNS

- Task 1: Implement `createQuery()` which builds a query based on the user input
- Task 2: Implement `sendQuery()` which opens a connection to the server and sends the query. 
- Task 3: Implement `responseHandler()` which prints the query response in a human readable way to the console.


- Milestone 3: Add the cryptographic part to the RAINS server.

- Task 1: Implement `verify()`, `reap()` which removes expired entries from cache 1 and the two caches
    - cache 1: contains public zone keys. (Before usage they must be checked for validity!)
    - cache 2: pending query map from identifying public key params to a list of open queries waiting to be verified by this public key. (avoid several equal requests)
- Task 2: Implement `delegate()` which adds a new element to the cache and verifies the pending queries with the key.
- Task 3: Write tests for `verify.go`.


- Milestone 4: Implement rainspub, which generates signed assertions. Including tests which ensure that rainspub is working correctly.


- Milestone 5: Implement a command line tool which interacts with rainspub and allows you to generate and publish signed assertions to a RAINS server.


- Milestone 6: Write a monitoring service which based on the logs lets us perform benchmark and performance tests in different production environments.


- Milestone 7: Improve metric based on which a RAINS server proactively forwards additional assertions based on a single query. 
  (E.g. by using machine learning we can find out that if a user is visiting page x.com then he is likely to access also y.com and z.com)


General Remarks:
- We use the log15 from https://github.com/inconshreveable to generate structured logs. 
  Log all performance critical actions such that we can afterwards easily build a monitoring service.
  Log meaningful information in a concise way about failures to help fix errors. 
- Can we detect if there are a lot of pushed assertions with the intention to fill the cache with lots of unimportant data. 
- There are four possible ways to handle inconsistencies.
    - Hard:         An Assertion/Shard/Zone is valid until it expires. On a conflicting input message return an inconsistency response. Keep the cache as it is.
    - Semi-Hard:    An Assertion/Shard/Zone is valid until it expires. On a conflicting input message remove all conflicting parts from the cache. Send inconsistency flag back.
                    The next incoming answer will then be consistent.
    - Soft:         An Assertion/Shard/Zone is valid until one encounters an Assertion/Shard/Zone which has a signature which is more recent. 
                    In this case discard all old data which is conflicting.
    - Revocation:   Use a Hash-chain to allow explicit revocation of an Assertion/Shard/Zone.
- Exclusion vs Isolation