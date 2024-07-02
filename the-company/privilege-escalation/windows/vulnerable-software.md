# Vulnerable software

Dump information if can gather on installed software

* wmic product get name,version,vendor

Be careful; due to some backward compatibility issues (e.g. software written for 32 bits systems running on 64 bits), the `wmic product` command may not return all installed programs. The target machine attached to this task will provide you with some hints. You will see shortcuts for installed software, and you will notice they do not appear in the results of the `wmic product` command. Therefore, It is worth checking running services using the command below to have a better understanding of the target system.

* `wmic service list brief`

As the output of this command can be overwhelming, you can grep the output for running services by adding a `findstr` command as shown below.

* `wmic service list brief | findstr  "Running"`



If you need more information on any service, you can simply use the `sc qc` command as seen below.

```shell-session
C:\Users\user>sc qc RemoteMouseService
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: RemoteMouseService
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files (x86)\Remote Mouse\RemoteMouseService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : RemoteMouseService
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

C:\Users\user>
```
