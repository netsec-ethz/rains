# Reverse zone key cache
NOT READY FOR REVIEW

## ideas
- trie data structure to find most specific public key. 0/0 (the trie's root) holds IANA's root
  public key. IANA can delegate different sub spaces of the network to other entities.
- Workflow:
  1. lookup most specific public key
  2. Verify signature. If it is valid, pass section to engine.
  3. (sig not valid) Send a delegation query for the subjectAddress. section on pending sig cache.
  4. on callback: verify signature. if it is valid, pass section to engine. Otherwise drop it.