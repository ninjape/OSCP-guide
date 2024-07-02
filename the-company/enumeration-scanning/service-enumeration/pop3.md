# POP3

## Connection

```
telnet <IP> <port>
```

## Vuln scanning

`nmap --script "pop3-capabilities or pop3-ntlm-info" -sV -p106 10.10.10.4`
