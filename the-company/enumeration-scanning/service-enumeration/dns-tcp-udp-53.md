# DNS - TCP/UDP 53

## Linux

### host

### &#x20;

```
host www.megacorpone.com
host -t mx megacorpone.com
host -t txt megacorpone.com
host idontexist.megacorpone.com
```

```
for ip in $(cat list.txt); do host $ip.megacorpone.com; done
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
```

### dnsrecon

```
dnsrecon -d megacorpone.com -t std
dnsrecon -d megacorpone.com -D ~/list.txt -t brt
```

### dnsenum

```
dnsenum megacorpone.com
```

## Resolve from DNS server

```
dig @10.129.146.146 htb.local

; <<>> DiG 9.18.0-2-Debian <<>> @10.129.146.146 htb.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38130
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
; COOKIE: 0922f4024bb6a6b5 (echoed)
;; QUESTION SECTION:
;htb.local.                     IN      A

;; ANSWER SECTION:
htb.local.              600     IN      A       10.129.146.146

;; Query time: 63 msec
;; SERVER: 10.129.146.146#53(10.129.146.146) (UDP)
;; WHEN: Tue Feb 08 15:44:52 EST 2022
;; MSG SIZE  rcvd: 66

```

```
dig @10.129.146.146 forest.htb.local
```

## Looking for possible zone transfer

```
dig axfr @10.129.146.146 htb.local

; <<>> DiG 9.18.0-2-Debian <<>> axfr @10.129.146.146 htb.local
; (1 server found)
;; global options: +cmd
; Transfer failed.


dig axfr @10.129.95.180 egotistical-bank.local

; <<>> DiG 9.18.1-1-Debian <<>> axfr @10.129.95.180 egotistical-bank.local
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

## Windows

### nslookup

```
nslookup mail.megacorptwo.com
nslookup -type=TXT info.megacorptwo.com 192.168.50.151
```

```
kali@kali:~/htb/monteverde$ nslookup 
> server 10.10.10.172
Default server: 10.10.10.172
Address: 10.10.10.172#53
> 127.0.0.1
1.0.0.127.in-addr.arpa	name = localhost.
> 10.10.10.172
;; connection timed out; no servers could be reached

> megabank.local
Server:		10.10.10.172
Address:	10.10.10.172#53

Name:	megabank.local
Address: 10.10.10.172
Name:	megabank.local
Address: dead:beef::10f
Name:	megabank.local
Address: dead:beef::edb5:e543:3a71:bf29
> 

```

##

```
```
