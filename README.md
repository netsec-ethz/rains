# RAINS, Another Internet Naming Service

This repository will contain a reference implementation of a RAINS server,
supporting authority, intermediary, and query service, as well as associated
tools for managing the server. It has the following entry points:

- `rainsd`:   A RAINS server
- `rainsdig`: A command-line RAINS client for query debugging
- `rainspub`: A command-line RAINS authority client for 
              publishing assertions to an authority service
- `rainsfic`: A tool for generating assertions to publish for
              publishing with `rainspub` for testing purposes.

In addition, the `rainslib` library on which the server and tools are built
provides common handling for the CBOR-based RAINS information model, and the
client-side RAINS stub resolver (...bonus points for integrating this with
Go's net. package in an idiomatic way...)


## Understanding RAINS

The development of the RAINS server and tools is currently in early design
phase. The detailed design of each component is given in that component's
design document:

- The [rainsd](internal/pkg/rainsd/DESIGN.md) design document
- The [rainsdig](rainsdig/DESIGN.md) design document
- The [rainspub](internal/pkg/publisher/DESIGN.md) design document
- The [rainsfic](rainsfic/DESIGN.md) design document
- The [rainslib](internal/pkg/DESIGN.md) design document

A general project plan for RAINS development is given [here](PROJECT-PLAN.md);
small matters of programming appear in the 
[issue tracker](https://github.com/netsec-ethz/rains/issues/).
