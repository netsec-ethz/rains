rdig(1) -- A RAINS query tool
=================================

## SYNOPSIS

`rdig` [options] QUALIFIED-SUBJECT

QUALIFIED-SUBJECT := SUBJECT-NAME [... SUBJECT-NAME]
SUBJECT-NAME := LABEL.[...LABEL].

## DESCRIPTION

rdig (short for RAINS dig) is a tool for querying RAINS servers from the command line. It performs lookups of the provided domain names and prints the results on the command line.

The queries are sent to the resolvers specified in the */etc/rains.conf* file, unless it is told to use a specific server via command line arguments.

When no command line arguments are specified, then 

## OPTIONS

* `-c`, `--context`:
    The context within which to query for assertions. For example to query within the global context `.` would be used as the context, or to query within a specific context such as `inf.ethz.ch`, that context can be specified with this options.

* `-t`, `--type`:
    The type of assertions to query for in the naming system. The following types are supported:
        * `D` / `DEL` -- Delegation record: a public key that identifies the authority,
        * `R` / `RED` -- Redirection record: names of one or more rains servers that provide authoritative service for the authority associated with the zone,
        * `A` / `ADDR` -- Address record: an IPv4 or IPv6 address for the given name,
        * `S` / `SRVI` -- Service Information record: A layer 4 address for a service published in the naming system,
        * `C` / `CERT` -- Certificate record: A certificate which must appear in the certificate chain presented on a connection attempt,

* `-n`, `--nonce`:
    Specify a nonce to be used in the query instead of using a randomly generated one.

## EXAMPLES

Simple query for the address associated to the name of www.inf.ethz.ch:

rdig -t A www.inf.ethz.ch

Querying the certificates which are used to authenticate connections to www.inf.ethz.ch:

rdig -t C www.inf.ethz.ch

Finding the name `simplon` within the context of inf.ethz.ch:

rdig -c inf.ethz.ch simplon
