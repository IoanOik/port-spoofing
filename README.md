# Port-Spoofing

This is a proof-of-concept tool that aims to complicate the "reconnaissance" process of a malicious actor.
During a port scan, it is common to see multiple ports receiving tcp syn messages, which indicates a connection request from a supposed client.  

However, the positive, negative or lack of response from the server side provides useful information about the system, from which the malicious actor can benefit by constructing a targeted attack scheme.  

In that context, the [libpcap](https://www.tcpdump.org/) and [libnet](https://github.com/libnet/libnet) libraries were used to identify such incoming packets and send appropriate syn-ack responses from every port (except those specified by the user). By the end of the scan, the port-scanner will have received a multitude of false positive indicators, which can maybe push the attacker into applying more "noisy" scans that are more likely to leave footprints.



```
user@hostname:~$ sudo nmap -sS 192.168.1.11 -F

Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-04 00:17 EET
Nmap scan report for 192.168.1.11
Host is up (0.67s latency).

PORT      STATE  SERVICE
7/tcp     open   echo
9/tcp     open   discard
13/tcp    open   daytime
21/tcp    open   ftp
22/tcp    closed ssh
23/tcp    open   telnet
25/tcp    open   smtp
26/tcp    open   rsftp
37/tcp    open   time
53/tcp    open   domain
79/tcp    open   finger
80/tcp    closed http
81/tcp    open   hosts2-ns
88/tcp    open   kerberos-sec
106/tcp   open   pop3pw
110/tcp   open   pop3
111/tcp   open   rpcbind
113/tcp   open   ident
119/tcp   open   nntp
135/tcp   open   msrpc
139/tcp   open   netbios-ssn
143/tcp   open   imap
144/tcp   open   news
179/tcp   open   bgp
199/tcp   open   smux
389/tcp   open   ldap
427/tcp   open   svrloc
443/tcp   closed https
444/tcp   open   snpp
445/tcp   open   microsoft-ds
465/tcp   open   smtps
513/tcp   open   login
514/tcp   open   shell
515/tcp   open   printer
543/tcp   open   klogin
544/tcp   open   kshell
548/tcp   open   afp
554/tcp   open   rtsp
587/tcp   open   submission
631/tcp   open   ipp
646/tcp   open   ldp
873/tcp   open   rsync
990/tcp   open   ftps
993/tcp   open   imaps
995/tcp   open   pop3s
1025/tcp  open   NFS-or-IIS
1026/tcp  open   LSA-or-nterm
1027/tcp  open   IIS


// TRIM


5900/tcp  open   vnc
6000/tcp  open   X11
6001/tcp  open   X11:1
6646/tcp  open   unknown
7070/tcp  open   realserver
8000/tcp  open   http-alt
8008/tcp  open   http
8009/tcp  open   ajp13
8080/tcp  open   http-proxy
8081/tcp  open   blackice-icecap
8443/tcp  open   https-alt
8888/tcp  open   sun-answerbook
9100/tcp  open   jetdirect
9999/tcp  open   abyss
10000/tcp open   snet-sensor-mgmt
32768/tcp open   filenet-tms

Nmap done: 1 IP address (1 host up) scanned in 1.85 seconds

```
