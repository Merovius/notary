# Notary - use roughtime as a trusted timestamp agent

This repository contains two things:

* A client implementation of the [roughtime
  protocol](https://roughtime.googlesource.com/roughtime/), in the roughtime
  package.
* A small tool called *notary*, which uses the roughtime protocol to obtain a
  cryptographic proof that a given file exists at the current time.

The notary tool achieves this by calculating a cryptographic hash of the given
file and using it as the initial nonce in a [roughtime request
chain](https://roughtime.googlesource.com/roughtime/+/HEAD/ECOSYSTEM.md#chaining-requests).
The servers in the chain then sign this nonce, together with their view of what
the current time is. The resulting chain can then be stored and used as proof
that the file existed previously (as long as at least one server in the chain
is trusted).
