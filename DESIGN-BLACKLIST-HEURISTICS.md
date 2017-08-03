# Blacklist heuristics

Future work. Still, some thoughts that popped up in discussion are mentioned here.

- All incoming messages are logged such that an external service can analyse it and decide if a zone
  or IP address will be blacklisted.
- Assertion(s) in response to a delegation query not all containing either a public key, an IP4, an
  IP6 or a redirect object for the queried zone are extracted from the logs and the zone's possibly
  blacklisted. We do not want to allow normal assertion(s) to take the path over the priority queue
  although they are not. (An assertion containing one of the four object types and several more is
  fine). The same applies for shards where the queried name is not in the shard range.
- Blacklist policy depends on the RAINS server topology.
