# SUID

`find / -type f -perm -04000 -ls 2>/dev/null` will list files that have SUID or SGID bits set.

A good practice would be to compare executables on this list with GTFOBins ([https://gtfobins.github.io](https://gtfobins.github.io/)). Clicking on the SUID button will filter binaries known to be exploitable when the SUID bit is set (you can also use this link for a pre-filtered list [https://gtfobins.github.io/#+suid](https://gtfobins.github.io/#+suid))



We see that the nano text editor has the SUID bit set by running the `find / -type f -perm -04000 -ls 2>/dev/null` command.\
\
`nano /etc/shadow` will print the contents of the `/etc/shadow` file. We can now use the unshadow tool to create a file crackable by John the Ripper. To achieve this, unshadow needs both the `/etc/shadow` and `/etc/passwd` files.

\


![](https://i.imgur.com/DAWxbJD.png)

The unshadow tool’s usage can be seen below;\
`unshadow passwd.txt shadow.txt > passwords.txt`\


![](https://i.imgur.com/6cHBAr1.png)



The other option would be to add a new user that has root privileges. This would help us circumvent the tedious process of password cracking. Below is an easy way to do it:

\


We will need the hash value of the password we want the new user to have. This can be done quickly using the openssl tool on Kali Linux.

\


\


![](https://i.imgur.com/bkOGaHY.png)

\


We will then add this password with a username to the `/etc/passwd` file.

\


![](https://i.imgur.com/huGoEtj.png)

\


Once our user is added (please note how `root:/bin/bash` was used to provide a root shell) we will need to switch to this user and hopefully should have root privileges.

\


![](https://i.imgur.com/HZcWGhi.png)

read files with base64

base64 /etc/shadow | base64 --decode
