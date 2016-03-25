# udpbeamer #

Debugging UDP connection problems.

Say you have a machine A and a machine B. Machine A sends UDP packets to machine
B. Sometimes packets seem to get lost. But you are not sure if there is a
problem with your software or your operating system or if there is a UDP related
network problem and the problem only occurs at random times. Such a problem can
be quite hard to debug.

With *udpbeamer* you install a little agent program (written in C) on machine
A. It captures the UDP packets in question with *libpcap*. Each packet is sent
over a TCP connection to machine B. On this machine the server component
(written in Python) is running. It sniffs for the incoming UDP packets and
compares them to the packets the agent announced to it on the TCP connection. If
a packet got announced but never arrives on machine B the server prints a warning.
