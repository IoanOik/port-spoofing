# Port-Spoofing

This is a proof-of-concept tool that aims to complicate the "reconnaissance" process of a malicious actor.
During a port scan, it is common to see multiple ports receiving tcp syn messages, which indicates a connection request from a supposed client.  

However, the positive, negative or lack of response from the server side provides useful information about the system, from which the malicious actor can benefit by constructing a targeted attack scheme.
In this context, the libpcap and libnet libraries were used to identify such incoming packets and send appropriate syn-ack responses from every port (except those specified by the user). In this way, the port-scanner will receive a multitude of false positive indicators, which can maybe push the attacker into applying more "noisy" scans that are more likely to leave footprints.