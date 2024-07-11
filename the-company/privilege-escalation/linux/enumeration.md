# Enumeration



## Enumeration

```
id
cat /etc/passwd
hostname
cat /etc/issue
cat /etc/os-release
uname -a

ps aux
ps -A
ps axjf
watch -n 1 "ps -aux | grep pass"

cat /proc/version
ip a
ss -anp
cat /etc/iptables/rules.v4
ls -lah /etc/cron*
crontab -l
sudo crontab -l
dpkg -l
sudo tcpdump -i lo -A | grep "pass"
```

{% code title="Listing all world writable directories and/or files" %}
```
find / -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null
```
{% endcode %}

{% code title="Listing content of /etc/fstab and all mounted drives" %}
```
cat /etc/fstab
mount
```
{% endcode %}

{% code title="Listing all available drives using lsblk" %}
```
lsblk
```
{% endcode %}

```
joe@debian-privesc:~$ lsmod
Module                  Size  Used by
binfmt_misc            20480  1
rfkill                 28672  1
sb_edac                24576  0
crct10dif_pclmul       16384  0
crc32_pclmul           16384  0
ghash_clmulni_intel    16384  0
vmw_balloon            20480  0
...
drm                   495616  5 vmwgfx,drm_kms_helper,ttm
libata                270336  2 ata_piix,ata_generic
vmw_pvscsi             28672  2
scsi_mod              249856  5 vmw_pvscsi,sd_mod,libata,sg,sr_mod
i2c_piix4              24576  0
button                 20480  0

```

{% code title="Displaying additional information about a module" %}
```
/sbin/modinfo libata
```
{% endcode %}

{% code title="Searching for SUID files" %}
```
find / -perm -u=s -type f 2>/dev/null
```
{% endcode %}

* env ### show environmental variables

![](https://i.imgur.com/LWdJ8Fw.png)

* cat /etc/passwd
  *   While the output can be long and a bit intimidating, it can easily be cut and converted to a useful list for brute-force attacks.



![](https://i.imgur.com/cpS2U93.png)

* Remember that this will return all users, some of which are system or service users that would not be very useful. Another approach could be to grep for “home” as real users will most likely have their folders under the “home” directory.

![](https://i.imgur.com/psxE6V4.png)

* cat /etc/fstab
* history
* ifconfig
* ip route
* `netstat -a`: shows all listening ports and established connections.
* `netstat -at` or `netstat -au` can also be used to list TCP or UDP protocols respectively.
* `netstat -l`: list ports in “listening” mode. These ports are open and ready to accept incoming connections. This can be used with the “t” option to list only ports that are listening using the TCP protocol (below)

![](https://i.imgur.com/BbLdyrr.png)

* `netstat -s`: list network usage statistics by protocol (below) This can also be used with the `-t` or `-u` options to limit the output to a specific protocol.

![](https://i.imgur.com/mc8OWP0.png)

* `netstat -tp`: list connections with the service name and PID information.

![](https://i.imgur.com/fDYQwbW.png)

This can also be used with the `-l` option to list listening ports (below)

![](https://i.imgur.com/JK7DNv0.png)

We can see the “PID/Program name” column is empty as this process is owned by another user.

Below is the same command run with root privileges and reveals this information as 2641/nc (netcat)\


![](https://i.imgur.com/FjZHqlY.png)

* `netstat -i`: Shows interface statistics. We see below that “eth0” and “tun0” are more active than “tun1”.

![](https://i.imgur.com/r6IjpmZ.png)

The `netstat` usage you will probably see most often in blog posts, write-ups, and courses is `netstat -ano` which could be broken down as follows;

* `-a`: Display all sockets
* `-n`: Do not resolve names
* `-o`: Display timers

![](https://i.imgur.com/UxzLBRw.png)

* find command
  * `find . -name flag1.txt`: find the file named “flag1.txt” in the current directory
  * `find /home -name flag1.txt`: find the file names “flag1.txt” in the /home directory
  * `find / -type d -name config`: find the directory named config under “/”
  * `find / -type f -perm 0777`: find files with the 777 permissions (files readable, writable, and executable by all users)
  * `find / -perm a=x`: find executable files
  * `find /home -user frank`: find all files for user “frank” under “/home”
  * `find / -mtime 10`: find files that were modified in the last 10 days
  * `find / -atime 10`: find files that were accessed in the last 10 day
  * `find / -cmin -60`: find files changed within the last hour (60 minutes)
  * `find / -amin -60`: find files accesses within the last hour (60 minutes)
  * `find / -size 50M`: find files with a 50 MB size



This command can also be used with (+) and (-) signs to specify a file that is larger or smaller than the given size.

![](https://i.imgur.com/pSMfoz4.png)

The example above returns files that are larger than 100 MB. It is important to note that the “find” command tends to generate errors which sometimes makes the output hard to read. This is why it would be wise to use the “find” command with “-type f 2>/dev/null” to redirect errors to “/dev/null” and have a cleaner output (below).

![](https://i.imgur.com/UKYSdE3.png)

\


Folders and files that can be written to or executed from:

* `find / -writable -type d 2>/dev/null` : Find world-writeable folders
* `find / -perm -222 -type d 2>/dev/null`: Find world-writeable folders
* `find / -perm -o w -type d 2>/dev/null`: Find world-writeable folders

The reason we see three different “find” commands that could potentially lead to the same result can be seen in the manual document. As you can see below, the perm parameter affects the way “find” works.

\


![](https://i.imgur.com/qb0klHH.png)

* `find / -perm -o x -type d 2>/dev/null` : Find world-executable folders

Find development tools and supported languages:

* `find / -name perl*`
* `find / -name python*`
* `find / -name gcc*`

Find specific file permissions:

Below is a short example used to find files that have the SUID bit set. The SUID bit allows the file to run with the privilege level of the account that owns it, rather than the account which runs it. This allows for an interesting privilege escalation path,we will see in more details on task 6. The example below is given to complete the subject on the “find” command.

* `find / -perm -u=s -type f 2>/dev/null`: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.

## Bash script to PING scan network

```
root@DANTE-WEB-NIX01:~# for i in {1..255} ;do (ping -c 1 172.16.1.$i | grep "bytes from"|cut -d ' ' -f4 | tr -d ':' &);done
<rep "bytes from"|cut -d ' ' -f4 | tr -d ':' &);done
172.16.1.5
172.16.1.10
172.16.1.12
172.16.1.13
172.16.1.17
172.16.1.19
172.16.1.20
172.16.1.100
172.16.1.101
172.16.1.102

```

## Bash script to scan for open ports

```
#!/bin/bash
host=10.5.5.11
for port in {1..65535}; do
timeout .1 bash -c "echo >/dev/tcp/$host/$port" &&
echo "port $port is open"
done
echo "Done"
```
