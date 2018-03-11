# Just For Fun DNS Server

Features:

- Resolution names in /etc/hosts 
- Relay queries to a DNS Server ip given
- Caching


```sh
emiliano sdserver  $ make
g++ -std=c++17 simple_dns_server.cpp -o simple_dns_server -levent
emiliano sdserver $ ./simple_dns_server -v
HOST_FILE = /etc/hosts
VERBOSE = yes
QUIET = no
NOCACHE = no
DNS = 8.8.8.8
++++ DNS Package +++++
ID: 49581
FLAG: 288
Question Count: 1
Answer Count: 0
Auth Count: 0
Additional: 1
Question => Name(www.facebook.com),Type(1),Class(1)
++++ DNS Package +++++
ID: 49581
FLAG: 33056
Question Count: 1
Answer Count: 1
Auth Count: 0
Additional: 1
Question => Name(www.facebook.com),Type(1),Class(1)
Answer => Name(www.facebook.com),Type(1),Class(1),TTL(0),RData(1.2.3.4)
```

Testing:

```sh
emiliano ~  $ dig @127.0.0.1 -p1053 www.facebook.com A
;; Warning: Message parser reports malformed message packet.

; <<>> DiG 9.12.0 <<>> @127.0.0.1 -p1053 www.facebook.com A
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 60423
;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;www.facebook.com.		IN	A

;; ANSWER SECTION:
www.facebook.com.	0	IN	A	1.2.3.4

;; Query time: 0 msec
;; SERVER: 127.0.0.1#1053(127.0.0.1)
;; WHEN: Fri Mar 02 14:29:49 -03 2018
;; MSG SIZE  rcvd: 66
```
