Most Talkative Host
===================

Intended to be bolted on to [MTC](https://github.com/nuviktor/mtc), this should allow me to auto-find the IP consuming the most bandwidth and print it to stdout. Only works for IPv4 and networks with at least 16 mask bits.

I've no previous experience in C so some of this could likely be cringeworthy.

The Makefile in the root directory integrates into the OpenWRT build process, so that I can cross-compile code to create binaries for my router.

Based heavily on [Tim Carstens' "Programming with pcap" tutorial](http://www.tcpdump.org/pcap.html).
