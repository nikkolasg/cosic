# cosic

Collective Signing (CoSi) bare bone alternate implementation in C. 

See https://github.com/dedis/cothority/app/cosi for more informations.

**WARNING**: This is highly experimental and is not guaranteed to always work. USE AT YOUR OWN RISK.

But still, it's fun.

# Why ? 

This project has one main goal: to make sure the Golang impl. is truly
compatible with other implementations and the reflect magic + custom protobuf
library does not make it Golang-dependant. So it's NOT a complete implementation
of the CoSi protocol but only for a leaf node of the tree. That avoids the
complexity of implementing the tree overlay which is not clearly defined (and is
also a bit too complex for what it should be).

# Implementation notes

* Written for >= C99
* dependency on libevent >= 2.0.22
* dependency on OpenSSL
* Supposed to be platform-independent, THOUGH there's still the `random_bytes`
  part which is for the moment hard coded for Linux (SYS_getrandom syscall)

# Ok but ... in C !?

Well, first why not ? :)
Then I wanted to do a real project in C for a long time to say "I've done it"
and by real I mean involving crypto + network + "complex" with differents parts
and not just a simple script.
That being said, it's far from being done: it misses some basic "object
oriented" pattern in C, and is not stable, so there's *lot* of stuff to do yet so
it's a safe implementation.
