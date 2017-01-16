# rainslib Design

rainslib implements the RAINS data model and marshaling/unmarshaling therefor (in `model.go`) as well as entry points for RAINS clients (in `client.go`)

## data model marshaling and unmarshaling design {#datamodel}

looks like we have to write our own CBOR serialization/deserialization due to
two complications:

- RAINS requires canonical CBOR for signing that CBOR libraries may not honor.
- Moving RAINS to CSON, which might make sense, would require a CSON library, 
  which doesn't exist yet, but should integrate with the CBOR library.
- RAINS specifies integer keys for extensible maps for efficiency, and 
  supporting integers in structure tags requires special handling. 

One could/should hack an existing CBOR library to provide these two properties.

## zonefile Format {#zonefile}

`rainspub` takes input in the form of RAINS _zonefiles_. The RAINS zonefile
format is loosely inspired by the BIND zonefile format, designed to be easily
parsed with a recursive descent parser, and to be reasonably intuitively
readable to people familiar with RAINS' information model and Internet naming
in general.

A zonefile consists of zero or more zones or bare assertions:

`zonefile := (zone | bare-assertion)*`

A zone consists of a zone declaration and the assertions it contains:

`zone := ':Z:' context-name zone-name '[' contained-assertion* ']'`

A contained assertion inherits its zone and context name from its containing zone:

`contained-assertion := ':A:' subject-name '[' object* ']'`

while a bare assertion must also contain a zone-name and context name:

`bare-assertion := ':A:' context-name zone-name subject-name '[' object* ']'`

Objects are each prefixed by an object type, which determines how to interpret the object content:

```
object := ip4-object | ip6-object | name-object | delegation-object | redirection-object | service-object | certificate-object | infrakey-object | nameset-object | registrar-object | registrant-object`

ip4-object := ':ip4:' ip4-address

ip6-object := ':ip6:' ip6-address

name-object := ':name:' qualified-name

delegation-object := ':deleg:' key-algorithm key-data

redir-object := ':redir:' qualified-name

service-object := ':srv:' TBD

certificate-object := ':cert:' TBD

infrakey-object := ':infra' key-algorithm key-data

nameset-object := ':nameset:' nameset-expression

registrar-object := ':regr:' free-object-text

registrant-object := ':regt:' free-object-text
```

The zonefile format can also be used to render a human-readable version of a
RAINS message encoded in CBOR; in this case, it is necessary to represent
shards and signatures as well:

```
contained-shard := ':S:' range-begin range-end '[' contained-assertions ']'

bare-shard := ':S:' context-name zone-name range-begin range-end '[' contained-assertions ']'

signature-section := '(' signature* ')'

signature := :sig: valid-from valid-until key-algorithm signature-data
```

## short assertions and short queries

There is a fair amount of complexity involved in marshaling and unmarshaling
CBOR as defined in the RAINS protocol draft. Some of this complexity may be
removed from the draft based on experience with this prototype. Prototyping
will therefore work on "short assertions" and "short queries" instead. These
short assertions and queries take much of their structure from the zonefile
format. For initial prototyping, they are used both on the wire as well as for
display and debugging purposes.

An unsigned short assertion is a UTF-8 string of the form ":A: context zone
subject objtype value" where:

- context is the context of the assumption
- zone is the name of the subject zone
- subject is the subject name within the zone
- objtype is one of:
    - ip4 for an IPv4 address; value is parseable address in string form
    - ip6 for an IPv6 address; value is parseable address in string form
    - name for a name; value is name as string
    - deleg for a delegation; value is cipher number, space, delegation key as hex string
    - redir for a redirection; value is authority server name
    - infra for an infrastructure key; value is cipher number, space, key as hex string
    - cert for a certificate; not yet implemented
    - nameset for a nameset; not yet implemented
    - regr for a registrar; value is unformatted string
    - regt for a registrant; value is unformatted string
    - srv for service info; not yet implemented
- value may contain spaces

A signed short assertion is generated and verified over the unsigned short
assertion with a valid key for that assertion's zone. A signed short assertion
has the form ":sig: valid-from valid-until cipher-number signature unsigned-assertion" where:

- cipher-number is an integer identifying the cipher algorithm
- signature is hex-encoded.
- valid-from is an ISO8601 timestamp
- valid-until is an ISO8601 timestamp

Signatures are generated over the concatenation of a stub signature (i.e.,
valid-from valid-until cipher-number) to an unsigned assertion.

A short query has the form:

":Q: valid-until context subject objtype"

Note that unlike RAINS queries, short queries can only have a single context
and object-type. This simplification may carry over into the protocol.
