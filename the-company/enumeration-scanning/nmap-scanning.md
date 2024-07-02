# Nmap Scanning

```
```

## **Grab and scan open ports**

```
ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.175 | grep ^[0-9] | cut -d '/' -f
1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A 10.10.10.175
```

## **Fast scan on all ports**

```
sudo nmap -p- --min-rate 10000 -oA scans/forest-alltcp -vv 10.129.146.146
sudo nmap -p- --min-rate 10000 -oA scans/forest-alludp -vv 10.129.146.146
```

{% code overflow="wrap" %}
```
nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,60397 -oA scans/nmap-tcpscripts 10.129.146.146
```
{% endcode %}

**sudo nmap -sS -A -sC -sV -p- -vv --reason -oN nmap.txt \<IP>**

* \-sS - SYN scan
* \-A: Enable OS detection, version detection, script scanning, and traceroute
* \-sC  - equivalent to --script=default
* \-O - OS detection
* \-v: Increase verbosity level (use -vv or more for greater effect)
* \--reason: Display the reason a port is in a particular state
* \-F: Fast scan; it  top 100 insteaf top 1000

## NSE

Scripts location - /usr/share/nmap/scripts/

**--script safe** ## to run safe scripts categories

\--script "vuln" ## run vuln scripts

Get a list of all categories available

`grep -r categories /usr/share/nmap/scripts/`_`.nse | grep -oP '".`_`?"' | sort -u`





## Nmap scanning `techniques`

[https://nmap.org/book/man-briefoptions.html](https://nmap.org/book/man-briefoptions.html)

* ICMP scanning
  * ICMP echo request (type 8) with a ping reply (ICMP type 0) - _sudo nmap -PE -sn MACHINE\_IP/24_
  * ICMP timestamp request (type 13) with reply(type 14) - _nmap -PP -sn MACHINE\_IP/24_
  * ICMP Address Mask request (type 17) with a reply (type 18) - _nmap -PP -sn MACHINE\_IP/24_
* ARP scanning
  * nmap -PR -sn TARGETS
  * arp-scan -l ##sends a scan to all valid IPs on the local subnet
* TCP SYN Ping
  * nmap -PS -sn MACHINE\_IP/2
* TCP ACK Ping
  * sudo nmap -PA -sn MACHINE\_IP/24
* UDP Ping
  * sudo nmap -PA -sn MACHINE\_IP/24
* Discovery scan
  * nmap -sn 10.10.1.1-254 -vv -oA hosts
  * netdiscover -r 10.10.10.0/24
* TCP FIN(-sF), Null(-sN) and XMAS(-sX) scan
* Window scan - The TCP window scan is almost the same as the ACK scan; however, it examines the TCP Window field of the RST packets returned. On specific systems, this can reveal that the port is open. You can select this scan type with the option -sW.
* DNS server discovery
* NSE scripts scan
  * nmap -sV --script=vulscan/vulscan.nse (https://securitytrails.com/blog/nmap-vulnerability-scan)
* Run a full port scan
  * sudo nmap -p- -sS \<IP>
*   Run script scans on each port

    sudo namp --script

## SCAN IPv6

nmap -6 -p 53,80,88,135,389,445,464,593,636,3268,3269,5985,9389 -sCV -oA scans/nmap-tcpscripts-ipv6 dead:beef::b885:d62a:d679:573f

