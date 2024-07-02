---
description: check what open ports you have for outbound
---

# Check your egress open ports

Using this PS oneliner you can check which ports are open from 1 to 1024. If it is open it means that your firewall rules/ISP allow for this outbound connection.

{% code overflow="wrap" %}
```
PS> 1..1024 | % {$test= new-object system.Net.Sockets.TcpClient; $wait = $test.beginConnect("allports.exposed",$_,$null,$null); ($wait.asyncwaithandle.waitone(250,$false)); if($test.Connected){echo "$_ open"}else{echo "$_ closed"}} | select-string " "

<OUTPUT>
1 closed
2 open
3 open
4 open
5 open
6 open
7 open
8 open
9 open
10 open
11 open
12 open
13 open
```
{% endcode %}

{% hint style="info" %}
[https://www.blackhillsinfosec.com/poking-holes-in-the-firewall-egress-testing-with-allports-exposed/](https://www.blackhillsinfosec.com/poking-holes-in-the-firewall-egress-testing-with-allports-exposed/)
{% endhint %}
