# SMTP

##

## Enumeration and vuln scanning

`sudo nmap --script smtp* -p25 10.10.10.4`

## Command to check if a user exists

`VRFY root`

created a script as well called smtp.py to automate the checking if a user exists. /home/kali/offsec/tools/

## Command to ask the server if a user belongs to a mailing list

`EXPN root`

### Brute-force

```
hydra -P /usr/share/wordlistsnmap.lst $ip smtp -V
```

## Windows

```
Test-NetConnection -Port 25 192.168.50.8

install telnet on windows
dism /online /Enable-Feature /FeatureName:TelnetClient
telnet 192.168.50.8 25
```
