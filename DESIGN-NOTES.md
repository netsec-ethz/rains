# General Design decisions
- Queries are answered as soon as any queried information is available, i.e. a server does not wait
  until it can fully answer a query but already responds with partial information.
- A server should keep all public keys necessary to validate the signatures on all its cached
  sections. This allows the server to answer all delegation queries about sections it has sent out.
- A server should respond to a delegation query with all matching public keys it believes the
  querier is missing to check a signature. A server does not keep state which delegations it has
  already sent to another server.
- After a configurable maximum number of delegation requests not leading to a needed public key for
  a section, it will be dropped.
- A server should log all incoming messages and their content such that an external service can
  blacklist zones or IP addresses based on it and additional information.