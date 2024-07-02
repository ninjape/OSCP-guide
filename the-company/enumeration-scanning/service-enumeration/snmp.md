# SNMP

```
sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt

echo public > community
echo private >> community
echo manager >> community

for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips

onesixtyone -c community -i ips



```

|                        |                  |
| ---------------------- | ---------------- |
| 1.3.6.1.2.1.25.1.6.0   | System Processes |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path   |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units    |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name    |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts    |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Ports  |

> Table 1 - Windows SNMP MIB values
>
>
>
> Using snmpwalk to enumerate the entire MIB tree

```
snmpwalk -c public -v1 -t 10 192.168.50.15
```

Using snmpwalk to enumerate Windows users

```
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25
```

Using snmpwalk to enumerate Windows processes

```
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2
```

Using snmpwalk to enumerate installed software

```
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2
```

Using snmpwalk to enumerate open TCP ports

```
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3
```
