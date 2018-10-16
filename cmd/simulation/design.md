# Simulation Framework

The simulation framework will be incrementally made more realistic. These are the improvement steps.

1. Server listens and responds on a channel. Clients are able to send and receive messages from a
   server and log the delay
2. A resolver is able to perform a recursive lookup
3. Messages are cbor encoded and signed. Signatures are verified.
4. Non-existence queries are supported
5. Static delay is added to each connection pair
6. Nodes are grouped by country and continent. Depending on the location of the communication
   partner the delay is different but still static. (1ms country, 20ms continent, 150ms
   inter-continental)
7. Resolver cache can be pre loaded
8. Delay function which returns a changing delay value depending on the three delay classes
   (Draw from a normal distribution mean={1500μs,30ms,175ms}, variance={500,5,15})
9. Expiring sections are resigned by rainspub and pushed to authoritative server(s)

## TODOs

- get a list of all country TLDs and use them to generated TLD names.
- generate Trace from local and global zipf distribution
- create generic server config
- Generated zonefile size should be determined by zipf law. [http://www.registrarowl.com/report_domains_by_country.php]
