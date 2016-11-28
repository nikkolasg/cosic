# cosic

Collective Signing (CoSi) bare bone alternate implementation in C. 

**WARNING**: This is highly experimental and is not guaranteed to always work. USE AT YOUR OWN RISK.

But still, it's fun.

# protocol notes

This project has one main goal: to make sure the Golang impl. is truly
compatible with other implementations. The derived goals are: get back up on my
C skills, find complex-parts-of-the-protocol-that-don't-have-to-be...

# implementation notes

* Written for >= C99
* dependency on libevent >= 2.0.22
* Supposed to be platform-independant, THOUGH there's still the `random_bytes`
  part which is for the moment hardcoded for Linux (SYS_getrandom syscall)



