# RPC - TCP 135

## rpcclient

```
rpcclient 10.10.10.172 -U '%'
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]

rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Organization Management] rid:[0x450]
group:[Recipient Management] rid:[0x451]
group:[View-Only Organization Management] rid:[0x452]
group:[Public Folder Management] rid:[0x453]
group:[UM Management] rid:[0x454]
group:[Help Desk] rid:[0x455]
group:[Records Management] rid:[0x456]
group:[Discovery Management] rid:[0x457]
group:[Server Management] rid:[0x458]
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
group:[Security Reader] rid:[0x45c]
group:[Security Administrator] rid:[0x45d]
group:[Exchange Servers] rid:[0x45e]
group:[Exchange Trusted Subsystem] rid:[0x45f]
group:[Managed Availability Servers] rid:[0x460]
group:[Exchange Windows Permissions] rid:[0x461]
group:[ExchangeLegacyInterop] rid:[0x462]
group:[$D31000-NSEL5BRJ63V7] rid:[0x46d]
group:[Service Accounts] rid:[0x47c]
group:[Privileged IT Accounts] rid:[0x47d]
group:[test] rid:[0x13ed]

rpcclient $> querygroup 0x200  ### query groups for its members
        Group Name:     Domain Admins
        Description:    Designated administrators of the domain
        Group Attribute:7
        Num Members:1

rpcclient $> querygroupmem 0x200
        rid:[0x1f4] attr:[0x7]
        
rpcclient $> queryuser 0x1f4
        User Name   :   Administrator
        Full Name   :   Administrator
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :   Built-in account for administering the computer/domain
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Tue, 08 Feb 2022 10:59:33 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 31 Dec 1969 19:00:00 EST
        Password last set Time   :      Mon, 30 Aug 2021 20:51:59 EDT
        Password can change Time :      Tue, 31 Aug 2021 20:51:59 EDT
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x1f4
        group_rid:      0x201
        acb_info :      0x00000010
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000062
        padding1[0..7]...
        logon_hrs[0..21]...

rpcclient $> querydispinfo
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail      Name: (null)    Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela       Name: (null)    Desc: (null)
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette      Name: (null)    Desc: (null)
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika       Name: (null)    Desc: (null)
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire       Name: (null)    Desc: (null)
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude       Name: (null)    Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia      Name: (null)    Desc: (null)
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred Name: (null)    Desc: (null)

```

```

rpcdump [-p port] 192.168.189.1
```

```
use auxiliary/scanner/dcerpc/endpoint_mapper
use auxiliary/scanner/dcerpc/hidden
use auxiliary/scanner/dcerpc/management
use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor
rpcdump.py <IP> -p 135
```

RPC or Remote Procedure Call, is an IPC (InterProcess Communication) mechanism which allows remote invocation of functions. This can be done locally on the server or via network clients. Distributed Component Object Model (DCOM) allows applications to expose objects and RPC interfaces to be invoked via RPC.&#x20;

```
rpcmap.py 'ncacn_ip_tcp:10.10.10.213' | grep -A2 'DCOM'
```

A list of available interfaces provided by DCOM can be enumerated using impacket's rpcmap.py .&#x20;

```
impacket-rpcmap 'ncacn_ip_tcp:10.129.89.36' | grep -A2 'DCOM'impacket-rpcmap 'ncacn_ip_tcp:10.129.89.36' | grep -A2 'DCOM'
```

{% hint style="info" %}
Check APT from HTB writeup\
[https://0xdf.gitlab.io/2021/04/10/htb-apt.html#recon](https://0xdf.gitlab.io/2021/04/10/htb-apt.html#recon)

BlackHills has a [good post on this](https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/)
{% endhint %}

TCP 135 is the Endpoint Mapper and Component Object Model (COM) Service Control Manager. There’s a tool called `rpcmap.py` from [Impacket](https://github.com/SecureAuthCorp/impacket/) that will show these mappings. This tool needs a `stringbinding` argument to enable it’s connection. The examples from `-h` are:

> stringbinding String binding to connect to MSRPC interface, for example: ncacn\_ip\_tcp:192.168.0.1\[135]\
> ncacn\_np:192.168.0.1\[\pipe\spoolss]\
> ncacn\_http:192.168.0.1\[593]\
> ncacn\_http:\[6001,RpcProxy=exchange.contoso.com:443]\
> ncacn\_http:localhost\[3388,RpcProxy=rds.contoso:443]

`NCANCN_IP_TCP` is an [RPC connection directly over TCP](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-rpce/95fbfb56-d67a-47df-900c-e263d6031f22). That seems like a good place to start. Running that gives a list of RPC mappings:

```
oxdf@parrot$ rpcmap.py 'ncacn_ip_tcp:10.10.10.213'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
...[snip]...
Protocol: [MS-DCOM]: Distributed Component Object Model (DCOM) Remote
Provider: rpcss.dll
UUID: 99FCFEC4-5260-101B-BBCB-00AA0021347A v0.0
...[snip]...
```

This scan provided a bunch of RPC endpoints with their UUIDs. The MS-DCOM ones are defined on [this page](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dcom/c25391af-f59e-40da-885e-cc84076673e4). The one shown above is the RPC interface UUID for IObjectExporter, or the IOXIDResolver. This is know that is used for the [Potato exploits](https://2020.romhack.io/dl-2020/RH2020-slides-Cocomazzi.pdf). [This article](https://airbus-cyber-security.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/) shows how to use this interface to get a list of network interfaces without auth.
