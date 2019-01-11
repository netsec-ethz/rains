# Zone File Format

A zone file is a text file containing a textual representation of RAINS entries. It is formatted in
a way that it is convenient for a human to read it. Typically, a zone file describes all entries of a
zone. But it can as well be used to pre-load caches of a RAINS server or a cache to output the
currently stored entries. It is also intended to display the response of a server when using
rainsdig, a command line tool similar to dig.

## Specification

A zone file contains a section or a sequence of sections. A section typically starts on a new line.
Each section consists of several elements. At least one white space (space, tab, return) acts as a
delimiter between elements. A comment starts with a ";" (semicolon) which results in the rest of the
line being ignored by the parser. Empty lines are allowed anywhere in the file, with or without
comments. There are three special encodings:

* ";" represents the beginning of a comment. The remainder of the line is ignored.
* "<" represents the nil value of a shard’s rangeFrom.
* ">" represents the nil value of a shard’s rangeTo.

### Format specification in backus normal form (BNF)

```
<sections> ::=  "" | <sections> <assertion> | <sections> <shard> | <sections> <pshard> | <sections> <zone>
<zone> ::=  <zoneBody> | <zoneBody> <annotation>
<zoneBody> ::= ":Z:" <subjectZone> <context> "[" <zoneContent> "]"
<zoneContent> ::= "" | <zoneContent> <assertion>
<shard> ::= <shardBody> | <shardBody> <annotation>
<shardBody> ::=  ":S:" <subjectZone> <context> <shardRange> "[" <shardContent> "]"
<shardRange> ::= <rangeBegin> <rangeEnd> | <rangeBegin> ">" | "<" <rangeEnd> | "<" ">"
<shardContent> ::= "" | <shardContent> <assertion>
<pshard> ::= <pshardBody> | <pshardBody> <annotation>
<pshardBody> ::= ":P:" <subjectZone> <context> <shardRange> <bfAlgo> <bfHash> <bloomFilterData>
<bfAlgo> ::= ":bloomKM12:" | ":bloomKM16:" | ":bloomKM20:" | ":bloomKM24:"
<bfHash> ::= ":shake256:" | ":fnv64:" | ":fnv128:"
<assertion> ::= <assertionBody> | <assertionBody> <annotation>
<assertionBody> ::= ":A:" <name> "[" <objects> "]" | ":A:" <name> <subjectZone> <context> "[" <objects> "]"
<objects> ::= <name> | <ip6> | <ip4> | <redir> | <deleg> | <nameset> | <cert> | <srv> | <regr> 
              | <regt> | <infra> | <extra> | <next>
<name> ::= <namebody> | <name> <namebody>
<ip6> ::= <ip6body> | <ip6> <ip6body>
<ip4> ::= <ip4body> | <ip4> <ip4body>
<redir> ::= <redirbody> | <redir> <redirbody>
<deleg> ::= <delegbody> | <deleg> <delegbody>
<nameset> ::= <namesetbody> | <nameset> <namesetbody>
<cert> ::= <certbody> | <cert> <certbody>
<srv> ::= <srvbody> | <srv> <srvbody>
<regr> ::= <regrbody> | <regr> <regrbody>
<regt> ::= <regtbody> | <regt> <regtbody>
<infra> ::= <infrabody> | <infra> <infrabody>
<extra> ::= <extrabody> | <extra> <extrabody>
<next> ::= <nextbody> | <next> <nextbody>
<namebody> ::= ":name:" <cname> "[" <objectTypes> "]"
<ip6body> ::= ":ip6:" <ip6Addr>
<ip4body> ::= ":ip4:" <ip4Addr>
<redirbody> ::= ":redir:" <redirname>
<delegbody> ::= ":deleg:" ":ed25519:" <keyphase> <publicKeyData>
<namesetbody> ::= ":nameset:" <freeText>
<certbody> ::= ":cert:" <protocolType> <certificatUsage> <hashType> <certData>
<srvbody> ::= ":srv:" <serviceName> <port> <priority>
<regrbody> ::= ":regr:" <freeText>
<regtbody> ::= ":regt:" <freeText>
<infrabody> ::= ":infra:" ":ed25519:" <keyphase> <publicKeyData>
<extrabody> ::= ":extra:" ":ed25519:" <keyspace> <keyphase> <publicKeyData>
<nextbody> ::= ":next:" ":ed25519:" <keyphase> <publicKeyData> <validFrom> <validSince>
<objectTypes> ::= <objectType> | <objectTypes> <objectType>
<objectType> ::= ":name:" | ":ip6:" | ":ip4:" | ":redir:" | ":deleg:" |  
                 ":nameset:" | ":cert:" | ":srv:" | ":regr:" | ":regt:" |  
                 ":infra:" | ":extra:" | ":next:" |
<freeText> ::= <word> | <freeText> <word>
<protocolType> ::= ":unspecified:" | ":tls:"
<certificatUsage> ::= ":trustAnchor:" | ":endEntity:"
<hashType> ::= ":noHash:" | ":sha256:" | ":sha384:" | ":sha512:" | ":fnv64:" | ":murmur364:"
<bfOpMode> ::= ":standard:" | ":km1:" | ":km2:"
<annotation> ::= "(" <annotationBody> ")"
<annotationBody> ::= <signature> | <annotationBody> <signature>
<signature> ::= <sigMetaData> | <sigMetaData> <signatureData>
<sigMetaData> ::= ":sig:" ":ed25519:" ":rains:" <keyphase> <validFrom> <validSince>
```

TODO: make it compatible with https://tools.ietf.org/html/rfc5234

## Example
```
:Z: com. . [
    :A: ns1.example [ 
            :ip6:      2001:0db8:85a3:0000:0000:8a2e:0370:7334
            :ip6:      2001:db8::68
    ]
    :A: ns1.example  [ :ip4: 192.168.1.11 ]
    :A: example [ :redir: ns.example.com. ]
    :A: example  [ :deleg: :ed25519: 5
    e28b1bd3a73882b198dfe4f0fa95403c5916ac7b97387bd20f49511de628b702
    ]
    :A: @  [ :cert: :tls: :endEntity: :sha256: e28b1bd3a73882b198dfe4f0fa954c ]
    :A: _rains._tcp.ns.example  [ :srv: ns1.example.com. 5022 0 ]
    :A: @  [ :regr: <registrar text> ]
    :A: @  [ :regt: <registrant info> ]
    
] ( :sig: :ed25519: :rains: 1 1547140919 1547155357 )
:S: com. . a f [
    :A: example [ :redir: ns.example.com. ]
    :A: example  [ :deleg: :ed25519: 5
    e28b1bd3a73882b198dfe4f0fa95403c5916ac7b97387bd20f49511de628b702
    ]
] ( :sig: :ed25519: :rains: 1 1547140919 1547155357 )
:P: com. . a d :bloomKM12: :shake256: e28b1bd3a73882b198dfe4f0fa95403c5916ac7b97387bd20f49511de6
( :sig: :ed25519: :rains: 1 1547140919 1547155357 )

:Z: example.com. . [
    :A: www  [ :name: w [ :ip4: :ip6: ] ]
    :A: www  [ :ip4: 192.168.1.10 ]
    :A: www [ 
            :ip6:      2001:0db8:85a3:0000:0000:8a2e:0370:7334
            :ip6:      2001:db8::68
    ]
] ( :sig: :ed25519: :rains: 1 1547140919 1547155357 )
```