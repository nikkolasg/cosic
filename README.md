# cosic

Collective Signing (CoSi) bare bone alternate implementation in C. 

See https://github.com/dedis/cothority/app/cosi for more informations.

**WARNING**: This is highly experimental and is not guaranteed to always work. USE AT YOUR OWN RISK.

It's also not finished !

But still, it's fun.

# Why ? 

This project has one main goal: to make sure the Golang impl. is truly
compatible with other implementations and the reflect magic + custom protobuf
library does not make it Golang-dependant. So it's NOT a complete implementation
of the CoSi protocol but only for a leaf node of the tree. That avoids the
complexity of implementing the tree overlay which is not clearly defined (and is
also a bit too complex for what it should be).

# How can I use it ?

Well, it's complex for the moment. You need to setup one Golang root node, with
one C leaf node, create the group toml corresponding and then launch the cosi
client to sign something... Yes, I've told you it's not ready yet :) I'm
planning to write a script to test it easily.

# Implementation notes

* Written for >= C99
* dependency on libevent >= 2.0.22
* dependency on OpenSSL
* Supposed to be platform-independent, THOUGH there's still the `random_bytes`
  part which is for the moment hard coded for Linux (SYS_getrandom syscall)

# Ok but ... in C !?

Well, first why not ? :)

It's been quite a long time now that I wanted to do a real project in C to 
say "I've done it". By real I mean involving crypto + network + "complex" 
with differents parts and not just a simple script.

That being said, it's far from being done: it misses some basic "object
oriented" pattern in C, and is not stable, so there's *lot* of stuff to do yet
so it can be called a safe implementation.
