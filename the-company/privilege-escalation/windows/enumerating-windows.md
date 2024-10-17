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
Get-ChildItem -Path C:\ -Include *.log -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```
{% endcode %}

`findstr /si password *.txt *.xml *.doc *.xls *.log`

Command breakdown:

`findstr`: Searches for patterns of text in files.

`/si`: Searches the current directory and all subdirectories (s), ignores upper case / lower case differences (i)

`password`: The command will search for the string “password” in files

`*.txt`: The search will cover files that have a .txt extension

## Listing env variables

{% code title="" overflow="wrap" lineNumbers="true" %}
```
 ls env:                                                                                                                                                                                                                       Name                           Value                                                                                    ----                           -----                                                                                    ALLUSERSPROFILE                C:\ProgramData                                                                           APPDATA                        C:\Users\emma\AppData\Roaming                                                            AppKey                         !8@aBRBYdb3!                                                                             CLIENTNAME                     kali                                                                                     CommonProgramFiles             C:\Program Files\Common Files                                                            CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files                                                      CommonProgramW6432             C:\Program Files\Common Files                                                            COMPUTERNAME                   EXTERNAL                                                                                 ComSpec                        C:\Windows\system32\cmd.exe                                                              DriverData                     C:\Windows\System32\Drivers\DriverData                                                   FPS_BROWSER_APP_PROFILE_STRING Internet Explorer                                                                        FPS_BROWSER_USER_PROFILE_ST... Default                                                                                  HOMEDRIVE                      C:                                                                                       HOMEPATH                       \Users\emma                                                                              LOCALAPPDATA                   C:\Users\emma\AppData\Local                                                              LOGONSERVER                    \\EXTERNAL                                                                               NUMBER_OF_PROCESSORS           2                                                                                        OS                             Windows_NT                                                                               Path                           C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPo... PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL                               PROCESSOR_ARCHITECTURE         AMD64           
```
{% endcode %}



## Listing files and folders contained

```
tree /a /f
```

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

## Git

Check if git is running and if there are any git repos.

```
git show
git status
git log
git show <commit-id>
```

Download whole git locally

```
wget -mirror -I .git http://192.168.190.144/.git
```

{% code title="Found deleted git files" %}
```
git status                                                                                                                               
On branch main
Your branch is ahead of 'origin/main' by 1 commit.
  (use "git push" to publish your local commits)

Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    README.md
        deleted:    api/export.php
        deleted:    api/index.php
        deleted:    api/order.php
        deleted:    configuration/database.php
        deleted:    orders/search.php
        deleted:    robots.txt

no changes added to commit (use "git add" and/or "git commit -a")
```
{% endcode %}

Recover git files

```
git checkout -- .    
git restore .
```

{% code title="recovered deleted files" %}
```
ls -lah
total 32K
drwxr-xr-x  6 kali kali 4.0K Oct 16 09:11 .
drwxr-xr-x  4 kali kali 4.0K Oct 16 09:09 ..
drwxr-xr-x  2 kali kali 4.0K Oct 16 09:11 api
drwxr-xr-x  2 kali kali 4.0K Oct 16 09:11 configuration
drwxr-xr-x 11 kali kali 4.0K Oct 16 09:11 .git
drwxr-xr-x  2 kali kali 4.0K Oct 16 09:11 orders
-rw-r--r--  1 kali kali   25 Oct 16 09:11 README.md
-rw-r--r--  1 kali kali   22 Oct 16 09:11 robots.txt

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

If you encounter any issues while using RunAs, you can try running an Administrator command prompt and entering the credentials for user backupadmin to obtain a shell.

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
