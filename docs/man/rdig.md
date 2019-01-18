rdig(1) -- A RAINS query tool
=================================

## SYNOPSIS

`rdig`  [@server] [options] [name] [type] [queryoptions...]

## DESCRIPTION

rdig (short for RAINS dig) is a tool for querying RAINS servers from the command line. It performs
lookups of the provided domain names and prints the results on the command line in zone file format.

## Simple Usage

A typical usage of dig looks like:

dig @server name type

where:
* server: is the IP address or a name of the RAINS server to which the query will be sent. The
    address can be an IPv4 address in dotted-decimal notation or an IPv6 address in colon-delimited
    notation. If the provided argument is a host name, rdig first resolves the IP address of that
    host before sending the actual query to this RAINS server. If no server argument is provided,
    dig consults /etc/resolv.conf and queries the name servers listed there.

* name: "is the fully qualified domain name of the Assertion that will be looked up"

* type: specifies the type for which rdig issues a query. Allowed types are: name, ip6, ip4, redir,
  deleg, nameset, cert, srv, regr, regt, infra, extra, next. If no type argument is provided, the
  type is set to ip6.

## OPTIONS

* `-t`, `--type`: specifies the type for which rdig issues a query. Allowed types are: name, ip6,
  ip4, redir, deleg, nameset, cert, srv, regr, regt, infra, extra, next. If no type argument is
  provided, the type is set to ip6.
* `-p`, `--port`: is the port number that rdig will send its queries to. The default port is 55553.
* `-k`, `--keyphase`: is the key phase for which a delegation is requested. The default key phase is
  0.
* `-c`, `--context`: specifies the context for which rdig issues a query. The default context is the
  global context '.'.
* `-e`, `--expires`: expires sets the valid until value of the query. A query expires after one
  second per default.
* `-i`, `--insecureTLS`: when set it does not check the validity of the server's TLS certificate.
  The certificate is checked by default.
* `-n`, `--nonce`: specifies a nonce to be used in the query instead of using a randomly generated
  one.

## QUERY OPTIONS

RAINS supports a set of query options to allow a querier to express preferences on how the query
should be handled. RAINS servers are not bound to these preferences. Query options are to be set in
priority order, i.e. to specify query options minEE and minIL with higher priority on minEE, write:
-minEE -minIL. Each query option is identified by a keyword.

* `-1`, `--minEE`: Minimize end-to-end latency
* `-2`, `--minAS`: Minimize last-hop answer size (bandwidth)
* `-3`, `--minIL`: Minimize information leakage beyond first hop
* `-4`, `--noIL`: No information leakage beyond first hop: cached answers only
* `-5`, `--exp`: Expired assertions are acceptable
* `-6`, `--tracing`: Enable query token tracing
* `-7`, `--noVD`: Disable verification delegation (client protocol only)
* `-8`, `--noCaching`: Suppress proactive caching of future assertions
* `-9`, `--maxAF`: Maximize answer freshness

## EXAMPLES

Simple query for the address associated to the name of www.inf.ethz.ch:

rdig www.inf.ethz.ch

Querying the certificates which are used to authenticate connections to www.inf.ethz.ch:

rdig www.inf.ethz.ch cert

Finding the name `simplon` within the context of inf.ethz.ch:

rdig -c inf.ethz.ch simplon
