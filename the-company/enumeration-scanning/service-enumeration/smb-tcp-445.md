# SMB - TCP 445

##

While modern implementations of SMB can work without NetBIOS, _NetBIOS over TCP_ (NBT) is required for backward compatibility and these are often enabled together. This also means the enumeration of these two services often goes hand-in-hand.

## Enumerate SMB shares

### enum4linux

Attempt to get the userlist (`-U`) and OS information (`-o`) from the target

`enum4linux -U -o <IP>`

`enum4linux -a <IP>`

enum4linux -a -u "" -p "" `<IP>`

### `nbtscan`

`nbtscan -r <IP>`

### crackmapexec

`crackmapexec smb dead:beef::b885:d62a:d679:573f --shares -u '' -p ''`

#### List all readable shares

```
crackmapexec smb 10.10.10.10 -u 'user' -p 'pass' -M spider_plus
```

![](<../../../.gitbook/assets/image (20).png>)

#### Dump all files

Using the option `-o READ_ONLY=false` all files will be copied on the host

```
crackmapexec smb 10.10.10.10 -u 'user' -p 'pass' -M spider_plus -o READ_ONLY=false
```

### smbmap

{% code overflow="wrap" %}
```
smbmap -H 10.10.10.161
smbmap -v -H 10.129.96.155           ### -v Return the OS version of the remote host
smbmap -H 10.10.10.161 -u 0xdf -p 0xdf
smbmap -H 10.129.89.36 -R --depth 10        ### list shares recursively; default depth is 5
smbmap -H 10.10.10.237 -R -u "%" -p "%"
```
{% endcode %}

### smbclient

<pre data-title="listing without a password" data-overflow="wrap" data-line-numbers><code>smbclient --no-pass //192.168.176.248/&#x3C;share>
smbclient -L \\172.16.1.10\         
smbclient -N -L //apt                         
smbclient -U '' //apt

c<a data-footnote-ref href="#user-content-fn-1">onnect to share without a password</a>
smbclient \\\\172.16.1.10\\SlackMigration
smb: \> ls
  .                                   D        0  Mon Apr 12 17:39:41 2021
  ..                                  D        0  Thu Aug 25 23:43:55 2022
  admintasks.txt                      N      279  Mon May 18 18:24:22 2020

                13758504 blocks of size 1024. 1532304 blocks available
smb: \> get admintasks.txt
getting file \admintasks.txt of size 279 as admintasks.txt (1.1 KiloBytes/sec) (average 1.1 KiloBytes/sec)
smb: \> exit


smblcient -U 'guest' //apt
smblcient -U 'anonymous' //apt
smbclient -U 'administrator' -L 10.129.88.203  ###enter blank password
smbclient -L spookysec.local -U svc-admin

Access a share
smbclient  '\\spookysec.local\backup' -U svc-admin
smbclient //10.10.10.100/Replication -U ""%""  #### login without a password
smbclient '\\10.129.89.36\Replication' -N      #### login without a password
</code></pre>

echo exit | smbclient -L \\\dead:beef::b885:d62a:d679:573f

```
smbclient \\\\dead:beef::b885:d62a:d679:573f\\backup
Enter WORKGROUP\oxdf's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Sep 24 03:30:52 2020
  ..                                  D        0  Thu Sep 24 03:30:52 2020
  backup.zip                          A 10650961  Thu Sep 24 03:30:32 2020

                10357247 blocks of size 4096. 6949719 blocks available
smb: \> get backup.zip
getting file \backup.zip of size 10650961 as backup.zip (6448.4 KiloBytes/sec) (average 6448.4 KiloBytes/sec)
```

#### Copy all files from an SMB share

```
root@kali# smbclient --user s.smith //10.10.10.182/Audit$ sT333ve2
Try "help" to get a list of possible commands.
smb: \> mask ""
smb: \> prompt OFF
smb: \> recurse ON
smb: \> lcd smb-audit-loot/
smb: \> mget *
getting file \CascAudit.exe of size 13312 as CascAudit.exe (191.2 KiloBytes/sec) (average 191.2 KiloBytes/sec)
getting file \CascCrypto.dll of size 12288 as CascCrypto.dll (206.9 KiloBytes/sec) (average 198.4 KiloBytes/sec)
getting file \DB\Audit.db of size 24576 as Audit.db (461.5 KiloBytes/sec) (average 275.3 KiloBytes/sec)
getting file \RunAudit.bat of size 45 as RunAudit.bat (0.8 KiloBytes/sec) (average 213.2 KiloBytes/sec)
getting file \System.Data.SQLite.dll of size 363520 as System.Data.SQLite.dll (3317.8 KiloBytes/sec) (average 1198.9 KiloBytes/sec)
getting file \System.Data.SQLite.EF6.dll of size 186880 as System.Data.SQLite.EF6.dll (356.4 KiloBytes/sec) (average 690.9 KiloBytes/sec)
getting file \x64\SQLite.Interop.dll of size 1639936 as SQLite.Interop.dll (4411.8 KiloBytes/sec) (average 1805.3 KiloBytes/sec)
```

## Mounting a share instead of downloading everything

{% hint style="info" %}
[https://www.linode.com/docs/guides/linux-mount-smb-share/#unmount-a-share](https://www.linode.com/docs/guides/linux-mount-smb-share/#unmount-a-share)
{% endhint %}



1.  Create an empty directory to be used as the mount point. This directory can be located wherever you wish, though it’s common to use the `/mnt` directory.

    ```bash
    mkdir /mnt/smb_share
    ```
2.  Enter the following command to mount the SMB share, replacing _\[server-ip]_ with the IP address of your SMB server, _\[share-path]_ with the file path to your SMB share on that server, and _\[mount-point]_ with the new directory you just created.

    ```bash
    mount -t cifs //[server-ip]/[share-path] /[mount-point]
    ```

    In the example below, the SMB server’s IP is 192.0.2.17, the share’s path is SharedFiles, and the mount point is `/mnt/smb_share`.

    ```bash
    mount -t cifs //192.0.2.17/SharedFiles /mnt/smb_share
    ```
3. When prompted, enter the password to connect to the remote share.
4.  If the connection is successful, you should see the remote share mounted on the mount point directory you created. To verify this, type the following command:

    ```bash
    mount -t cifs
    ```

### Unmount a Share <a href="#unmount-a-share" id="unmount-a-share"></a>

You may need to unmount a share at some point. To unmount an SMB share that has been mounted using the `mount` command, you can use the `umount` command followed by the mount point of the share. The correct command is `umount`, not `unmount`.

So to unmount an SMB share at the mount point `<Mount Point>`, run the following command:

```bash
umount -t cifs /<Mount Point>
```

## Nmap



nmap -v -p 139,445 --script=smb-os-discovery \<IP>

nmap -v -p 445 -script=smb-vuln-\* `<IP>`

## Windows

```
net view \\dc01 /all
```

##

[^1]: 
