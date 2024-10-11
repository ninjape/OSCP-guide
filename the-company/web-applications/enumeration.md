# Enumeration

##

{% hint style="info" %}
check robots.txt
{% endhint %}

## Nmap

```
sudo nmap -p80  -sV 192.168.50.20
sudo nmap -p80 --script=http-enum 192.168.50.20
```

## Nikto

* nikto -h \<IP>

## gobuster

{% code title="-b for blacklist and made it empty" overflow="wrap" lineNumbers="true" %}
```
gobuster dir -u https://<IP>/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -s '200,204,301,302,307,403,500' -e -b '' -x aspx,config,pdf
```
{% endcode %}

### gobuster with -x file\_type (aspx)

<pre data-overflow="wrap" data-line-numbers><code><strong>gobuster dir -u http://10.129.93.43/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -s '200,204,301,302,307,403,500' -e -t 30 -x aspx -b ''
</strong>===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) &#x26; Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.93.43/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              aspx
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2022/06/03 06:52:08 Starting gobuster in directory enumeration mode
===============================================================
http://10.129.93.43/aspnet_client        (Status: 301) [Size: 157] [--> http://10.129.93.43/aspnet_client/]
http://10.129.93.43/render/https://www.google.com.aspx (Status: 400) [Size: 11]                            
http://10.129.93.43/transfer.aspx        (Status: 200) [Size: 941]                                         
http://10.129.93.43/uploadedfiles        (Status: 301) [Size: 157] [--> http://10.129.93.43/uploadedfiles/]
                                                                                                           
===============================================================
2022/06/03 06:52:33 Finished
===============================================================
kali@kali:~$ 
</code></pre>

##

### through proxychains

{% code overflow="wrap" lineNumbers="true" %}
```
proxychains gobuster dir --proxy socks5://127.0.0.1:1080 --url http://172.16.1.12 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
```
{% endcode %}

## Dirb

* dirb http://sandbox.local

## Wpscan

* wpsn - wordpress vulnerability scanner

```
kali@kali:~$ wpscan --url sandbox.local --enumerate ap,at,cb,dbe
```

* ```
  whatweb -a 1 http://10.10.10.8 ## stealthy
  whatweb -a 3 http://10.10.10.8 ## aggresive

  ```
* interact with the website as a normal user from the browser and look for interesting stuff
* view page source
* use developer tools, inspector, debugger(firefox)/sources(chrome)
* check robots.txt
* check favicon icon
* check sitemap.xml
* check headers

## feroxbuster

{% code overflow="wrap" lineNumbers="true" %}
```
feroxbuster --url http://10.129.59.154 --depth 2 --wordlist /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
feroxbuster --url http://192.168.248.189 --depth 2 --wordlist /usr/share/wordlists/wfuzz/general/megabeast.txt 
```
{% endcode %}

{% hint style="info" %}
`feroxbuster` is a tool designed to perform [Forced Browsing](https://owasp.org/www-community/attacks/Forced\_browsing).

[https://github.com/epi052/feroxbuster](https://github.com/epi052/feroxbuster)
{% endhint %}

## wfuzz

{% code overflow="wrap" lineNumbers="true" %}
```
wfuzz -c -z file,usernames.txt -z file,passwords.txt --hs "Please enter the correct credentials" -u http://10.10.140.34/login.php -d "username=FUZZ&password=FUZ2Z"
```
{% endcode %}

## Wappalyzer
