---
cover: >-
  https://images.unsplash.com/photo-1552664730-d307ca884978?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=2970&q=80
coverY: 0
---

# Enumeration/Scanning

## Passive Reconnaissance

* whois - to query WHOIS servers
  * the syntax is _whois DOMAIN\_NAME_ or _whois OPTIONS DOMAIN\_NAME SERVER_
  * _whois tryhackme.org_
  * ```
    OPTIONS contains the query type as shown in the table below. For instance, you can use A for IPv4 addresses and AAAA for IPv6 addresses.
    DOMAIN_NAME is the domain name you are looking up.
    SERVER is the DNS server that you want to query. You can choose any local or public DNS server to query. Cloudflare offers 1.1.1.1 and 1.0.0.1, Google offers 8.8.8.8 and 8.8.4.4, and Quad9 offers 9.9.9.9 and 149.112.112.112. There are many more public DNS servers that you can choose from if you want alternatives to your ISP’s DNS servers.
    ```
  *
* nslookup - to query DNS servers
  * the sytax is _nslookup DOMAIN\_NAME_
  * _nslookup tryhackme.org_
* dig - to query DNS servers
  * _dig DOMAINNAME or dig DOMAIN\_NAME TYPE_
  * _eq. dig tryhackme.com MX_
  * _eq. dig @1.1.1.1 tryhackme.com MX_



## Finding DNS Names

1. First you need to scan to find out the DNS Server. Most simple way to do this is with nmap and scan port 53.
2. Check with nslookup if it resolvs a live IP or not
3. for ip in $(seq 1 255); do host 10.11.1.$ip 10.11.1.220; done | grep -v 'Address|Name|Aliases|Using|not' | grep -e "\r" > dns\_names.txt
