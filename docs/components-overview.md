# RAINS Components

This document is about the implementation design of the different components required to run RAINS.
It describes a command line querying tool called RainsDig, a command line key managing tool, a
highly configurable publishing tool called ZonePub, the two modes in which a RAINS server can run, a
recursive resolver, and how zone files are parsed.

## RainsDig

RainsDig is a command line tool that can be used to query RAINS servers. It outputs the response in
zone file format. In case an entry such as a query is not defined in the zone file format, it is
displayed in a similar fashion. It is designed to be similar to dig \cite{dig} which is used to
query DNS, to make everyone's life easy when transitioning from DNS to RAINS or using both. RainsDig
does not support dig's rarely used command line options to keep the tool simple and comprehensive.
There is a page describing RainsDig's functionality.

## ZonePub

ZonePub is a command line tool for zone authorities to publish a zone file to authoritative
server(s). It requires as input a path to a configuration file which specifies how the zone file
should be processed before being sent to the servers. This includes among others, grouping
assertions into shards and pshards, adding signature meta data to each section according to the
zone's delegation schedule(s), and performing consistency checks. All entries in the configuration
file can be overridden by providing the corresponding command line option. There is a man page
describing ZonePub's functionality.

## KeyManager

The key manager is intended for zone operators to generate, store, and load keys related to RAINS in
a simple way. When generating a new key pair, it allows an operator to choose the algorithm and key
phase and stores the public and the encrypted private key to disk at the provided path in pem
format. The private key is encrypted based on a password chosen by the zone operator. The key
manager can display all public keys stored in a directory and decrypt and print a private key
(provided the correct password was entered). There is a man page describing KeyManager's
functionality.

## RAINS Server

A RAINS server can be operated in two modes to meet the respective requirements. A RAINS server can
be operated as an authoritative server which holds all the information about one or several zones
and only answers queries about these zones and their respective subzones. Otherwise, it could be
used as a caching resolver which stores previously received answers to optimize query latency and
handles queries on several clients behalf. More information about the implementation design and the
different components of a RAINS server is stored in the TODO reference file.

## RAINS Recursive Resolver

A RAINS recursive resolver is a light weight implementation performing recursive lookups on behalf
of another component such as rainsDig or a RAINS server. It caches delegation assertions to quickly
verify signatures or answer a client's or server's delegation request. It is able to run in blocking
and non-blocking mode. In non-blocking mode a network address must be provided to which the answer
will be forwarded.

## Zonefile parser

Goyacc is used to create a RAINS zone file parser. Yacc is a parser generator which creates a parser
based on a grammar written in a notation similar to Backus–Naur Form (BNF). Each grammar rule is
coupled with an action which tells Yacc how to transform the input into a RAINS data structure. With
this automated approach, changes to the zone file format can quickly be integrated into the parser
by just updating the grammar rule and its action. Additionally, it reduces the probability of a bug
in the parser as Yacc is widely used. In case the input zone file is malformed, the generated parser
returns the line number and position in the zone file where it does not adhere to the format.

## Actors in the RAINS ecosystem

Different entities need different tools of the RAINS ecosystem. In this section, we list for each
entity which of the above described tools can be leveraged to successfully operate RAINS.

## Zone Authority

A zone authority wants to make information about its zone and all subzones available to the rest of
the network on its authoritative RAINS servers. To populate the authoritative servers with records
about its zone, the authority can use the zone publisher. The zone manager needs access to the
private keys of the zone which it can access through the keyManager. Each authoritative server is
also connected to a recursive resolver to obtain public keys of this zone's superordinate zones. The
zonefile parser is used by the zone publisher to read the information it is supposed to publish.
RainsDig could be used to check if all information about the zone has been successfully stored on
the authoritative servers.

## RAINS Query Service Provider (e.g. an ISP)

An intermediate who wants to provide a RAINS query service to its customers just needs to deploy at
least one RAINS server in caching mode and connect it to a recursive resolver.

## Client

A client only needs rainsDig which either forwards a query issued by the user to a configured RAINS
query service or performs the recursive lookup by itself using the recursive resolver which is
hooked into rainsDig.
