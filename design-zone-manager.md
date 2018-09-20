# How to manage a zone

This document presents a design how a zone authority could manage its zone.
Always when something needs to be changed on a current section or a section has
to be added or removed the zone authority handles it and makes sure that the
rainsd server gets a signed and updated section. We envision three components a
zone authority must have to efficiently manage its zone which we are going to
describe in detail below.

1. zone manager (zoneManager)
2. zone publisher (zonePub)
3. rains publisher (rainsPub)

## Zone manager

The zone manager is responsible for the administrative part. This involves to
deal with clients, manage contracts and make sure that the content of the signed
contracts are realized. This also means that it must keep the zone file up to
date. It might include grouping assertions into shards, sorting the zone, and
making sure that no entry violates the protocol specification or the zone's
policy. But it could as well delegate this task to the zone publisher. The zone
manager also invokes the zone publisher periodically to publish all or parts of
its sections to the system according to its policy. It handles next-key
assertions from its subzones and updates the delegation assertion's public key
in the zonefile accordingly

## Zone publisher

The zone publisher is a small, highly configurable command line tool. It uses
the rains publisher library which performs most of the work. It is periodically
invoked by the zone manager to push updated zone information to the rains
servers. It loads the information what to push from the zonefile provided by the
zone manager. The configurations are loaded from a config file and each of them
can be overwritten by providing the updated value as a command line flag. If the
signature meta data are not provided in the zonefile, the zone publisher
calculates them for each section according to its configuration (e.g. to expire
assertions evenly over a time interval). It can optionally make sure that the
new delegation assertion for this zone is present on all authoritative rains
servers and that the newly signed zone information is consistent before encoding
and pushing it to the rains servers. In case one of the rains servers has not
been able to correctly receive the update, the zone publisher raises an alarm.

## RAINS publisher

Rains publisher (rainsPub) is designed as a library to do most of the work
involved in updating zone information such as sign sections (assertions, shards,
and zones), establish connections to all authoritative servers and push the
newly signed sections to them, etc. It reports back to the zone publisher in
case errors have occurred. Currently, the private key is stored on the rainsPub
server but in the future an airgapping mechanism might be used to increase
security. RainsPub ignores any information sent from the rains servers except
notifications concerning a previously pushed section from rainsPub.
