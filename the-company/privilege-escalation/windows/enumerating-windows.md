# Enumerating Windows

## RDP command

```
xfreerdp /u:offsec /p:lab /v:192.168.158.62 /h:980 /w:1920
```

{% code title="To mount local drive /tmp to Windows RDP session" overflow="wrap" lineNumbers="true" %}
```
xfreerdp /u:offsec /p:lab /v:192.168.158.62 /h:980 /w:1920 /drive:/tmp 
```
{% endcode %}

## User enumeration

* `whoami /priv`  ###current user's privileges
* whoami /groups
* `net users` ###list users
* `net user <username>` (e.g. net user Administrator)
* `qwinsta` (other users logged in simultaneously - `query session`)
* net localgroup - user groups defined on the system
* net localgroup \<groupname> (eg net localgroup Administrators)

## Powershell

{% code title="" overflow="wrap" lineNumbers="true" %}
```
net user
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember adminteam
Get-LocalGroupMember Administrators
```
{% endcode %}

{% code title="" overflow="wrap" lineNumbers="true" %}
```
ls -force
gci -recurse -force -file PSTranscripts ## get powershell history
```
{% endcode %}

### Process type

Check under what type of process you have a shell.&#x20;

```
PS C:\Users\kostas\Desktop> [Environment]::Is64BitProcess
False
```

### History

{% code title="" overflow="wrap" lineNumbers="true" %}
```
Get-History
(Get-PSReadlineOption).HistorySavePath
type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\Public\Transcripts\transcript01.txt
```
{% endcode %}

{% code title="Using the commands from the transcript file to obtain a PowerShell session as daveadmin" overflow="wrap" lineNumbers="true" %}
```
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
whoami
```
{% endcode %}

{% code title="Retrieval of Script Block logging events" overflow="wrap" lineNumbers="true" %}
```
Get-WinEvent -FilterHashtable @{logname = "Microsoft-Windows-PowerShell/Operational"; id = 4104 } | select -ExpandProperty message
```
{% endcode %}

{% hint style="info" %}
[https://doitpshway.com/getting-powershell-script-block-logging-events-with-context-like-who-when-and-how-run-the-code](https://doitpshway.com/getting-powershell-script-block-logging-events-with-context-like-who-when-and-how-run-the-code)
{% endhint %}

## Collecting system information

```
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
hostname
wmic os get OSArchitecture  ## get OS architecture
ipconfig /all
route print
```

## Searching files

{% code title="" overflow="wrap" lineNumbers="true" %}
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```
{% endcode %}

`findstr /si password *.txt`

Command breakdown:

`findstr`: Searches for patterns of text in files.

`/si`: Searches the current directory and all subdirectories (s), ignores upper case / lower case differences (i)

`password`: The command will search for the string “password” in files

`*.txt`: The search will cover files that have a .txt extension



## Patch level

`wmic qfe get Caption,Description,HotFixID,InstalledOn`

&#x20;WMIC is deprecated in Windows 10, version 21H1 and the 21H1 semi-annual channel release of Windows Server. For newer Windows versions you will need to use the WMI PowerShell cmdlet. More information can be found [here](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/07-working-with-wmi?view=powershell-7.1).

## Applications

{% code title="PS command to get all installed applications on 32 and 64 bits" overflow="wrap" lineNumbers="true" %}
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
{% endcode %}

## Processes

{% code title="Get running processes" overflow="wrap" lineNumbers="true" %}
```
Get-Process
```
{% endcode %}

## Services

```
wmic service get name,displayname,pathname,startmode

###services that are automatically started
wmic service get name,displayname,pathname,startmode | findstr /i "auto"

###services that that are not started from c:\windows
wmic service get name,displayname,pathname,startmode |findstr /i "auto"
|findstr /i /v "c:\windows"
```

## Permissions on folders - icacls

```
C:\Users\alex>icacls "C:\Puppet"
C:\Puppet BUILTIN\Users:(W)
BUILTIN\Administrators:(I)(F)
BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
BUILTIN\Users:(I)(OI)(CI)(RX)
NT AUTHORITY\Authenticated Users:(I)(M)
NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)
```

## Network Connections

```
netstat -ano
```



The command above can be broken down as follows;

* `-a`: Displays all active connections and listening ports on the target system.
* `-n`: Prevents name resolution. IP Addresses and ports are displayed with numbers instead of attempting to resolves names using DNS.
* `-o`: Displays the process ID using each listed connection.

## RunAs

{% code title="Run cmd as a different user" overflow="wrap" lineNumbers="true" %}
```
runas /user:backupadmin cmd
```
{% endcode %}

## Scanning network with ping&#x20;

```
for /L %i in (1,1,255) do @ping -n 1 -w 200 10.5.5.%i > nul && e
cho 10.5.5.%i is up.
```

## Scheduled Tasks

schtasks /query /fo LIST /v



## Drivers

driverquery



## Antivirus

The query below will search for a service named “windefend” and return its current state.

`sc query windefend`

While the second approach will allow you to detect antivirus software without prior knowledge about its service name, the output may be overwhelming.

`sc queryex type=service`
