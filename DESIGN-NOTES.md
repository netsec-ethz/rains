# RAINS system design notes

## Arrangement of components

TODO

# Miscellany

## zonefile Format {#zonefile}

todo: describe the rains zonefile format here. inspired by BIND zonefiles,
close to the wire format, and designed to be easily RDP-parseable.




## data model marshaling and unmarshaling design {#datamodel}

looks like we have to write our own CBOR serialization/deserialization due to
two complications:

- RAINS requires canonical CBOR for signing that CBOR libraries may not honor.
- Moving RAINS to CSON, which might make sense, would require a CSON library, 
  which doesn't exist yet, but should integrate with the CBOR library.
- RAINS specifies integer keys for extensible maps for efficiency, and 
  supporting integers in structure tags requires special handling. 

One could/should hack an existing CBOR library to provide these two properties.
