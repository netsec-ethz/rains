# rainspub Design

TODO CFE, Design is deprecated. Rewrite README

`rainspub` takes input in the form of RAINS zonefiles (see
[the zonefile definition](../DESIGN-NOTES.md#zonefiles)) and a keypair for a zone,
generates signed assertions, shards, and zones, and publishes these to a set
of RAINS servers using the RAINS protocol.

Its design is fairly simple, based around a linear workflow:

- take as input a keypair, a zonefile, a set of server addresses, and sharding
  and validity parameters
- parse the zonefile into a set of unsigned assertions
- group those assertions into shards based on a set of sharding parameters
- sign assertions, shards, and zones with a validity specified by validity parameters
- connect to the specified servers and push the signed messages to them using the RAINS protocol
- listen for notification messages from the specified servers and log

an authority server (in the traditional, DNS-like sense) is therefore
constructed by running `rainspub` and `rainsd` at the same time, with
`rainspub` pushing only to the colocated `rainsd`.

Optional step: Airgapping
To make it harder for an adversary to steal a zone key, the machine holding the key (e.g. a laptop with possibly a camera) is inside a box which, once closed, cannot be opened.
The machine works as follows:
- Read in data to be signed with its camera by parsing a QR code.
- Sign the data using the private key.
- Generate a QR code of the signed data and display it on the screen
It needs to be verified if such a setup achieves high enough bandwidth.
