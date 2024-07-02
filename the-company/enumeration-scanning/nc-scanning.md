# nc scanning

```
nc -nvv -w 1 -z 192.168.50.152 3388-3390
nc -nv -u -z -w 1 192.168.50.149 120-123

-u - udp scanning
-w - connection timeout in seconds
-z - to specify zero-I/O mode, which is used for scanning and sends no data.
```
