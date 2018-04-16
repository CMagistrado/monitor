monitor
=======

The new Cuckoo Monitor. [Click here for documentation][docs].
If at first it doesn't compile, just try a second time!

[docs]: http://cuckoo-monitor.readthedocs.org/en/latest/

## To compile
Inside Linux shell:
```
$ make
```

NOTE: This will compile this binary for Windows 7. To change,
change the Makefile's "\_WIN32\_WINNT" value to something
else: https://msdn.microsoft.com/en-us/library/6sehtctf.aspx

## To use old signatures (from original monitor) in common with the full signatures (the ones we can scan and hook)
Inside Linux shell:
```
$ cd ./sigs/
$ cp ./template/sigs.rst-old-stable sigs.rst
```

Then recompile monitor.

This sigs.rst-old-stable file is compiled from the
old signatures in ./sigs-old

## To generate signatures for API calls that can be used to model behavior
Inside Linux shell:
```
$ cd ./sigs/modeling
$ python combine.py ../template/sigs.rst-full > ../sigs.rst 2>error
```

Any API calls not found in sigs.rst-full will be printed in "error"
Note that the "error" file already exists. This is the output
from the most recent run of combine.py and is kept for historic
purposes.

Combine.py searches through all \*.txt files within the modeling folder.
Each txt file contains a list of names of API calls we wish to hook.
This is easier to use than before, as you can automatically add new
hooked API calls by name, rather than adding them (their signatures)
manually by hand.

Then recompile monitor.

Functions hooked: [link](sigs/modeling)

Flags ignored/modified: [link](flags/README.md)

## To generate signatures for (most) API calls
Inside Developer Command Prompt (Windows):
```
$ cd get-symbols
$ python parse.py
```

Put the resulting sigs.rst file in ./sigs/template/sigs.rst-full

Note: Whilst this is a complete list of all API calls the parser
can see, it doesn't mean the monitor will compile. All objects and
data structures used by these calls may not be defined in this source.

In addition, this file is used by combine.py (mentioned above) to generate
the signature file for modeling behavior.

./get-symbols/parse.out is the output of running this script to retrieve
./sigs/template/sigs.rst-full. This is kept for historic reasons.

Note that hook every single API call may not be beneficial for your particular
needs. It will slow down the target program's execution and may be filled
with noise that isn't sufficient to model the program's behavior.

However, this is used to create the hooks used to model behaviors (see above).

Also note that this will remove all efforts to communicate back to the
analyzer (e.g., to tell it to hook into a child process). You must add
this back in after rescanning. See all lines in ./sigs/template/sigs.rst-full
that call pipe().

There were calls hooked by Cuckoo's old signatures that my parser didn't pickup:
  - CreateProcessInternalW
  - SetContextThread
  - IWbemServices_ExecMethod
  - URLDownloadToFileW
  - ActiveXObjectFncObj_Construct
  - CDocument_write
  - CElement_put_innerHTML
  - CertControlStore
  - CertCreateCertificateContext
  - CertOpenStore
  - CertOpenSystemStoreA
  - CertOpenSystemStoreW
  - CHyperlink_SetUrlComponent
  - CIFrameElement_CreateElement
  - CImgElement_put_src
  - CoCreateInstance
  - CoCreateInstanceEx
  - CoGetClassObject
  - CoInitializeEx
  - CoInitializeSecurity
  - COleScript_Compile
  - ConnectEx
  - CoUninitialize
  - CreateActCtxW
  - CreateToolhelp32Snapshot
  - CryptAcquireContextA
  - CryptAcquireContextW
  - CryptCreateHash
  - CryptDecodeMessage
  - CryptDecodeObjectEx
  - CryptDecrypt
  - CryptDecryptMessage
  - CryptEncrypt
  - CryptEncryptMessage
  - CryptExportKey
  - CryptGenKey
  - CryptHashData
  - CryptHashMessage
  - CryptProtectData
  - CryptProtectMemory
  - CryptUnprotectData
  - CryptUnprotectMemory
  - CScriptElement_put_src
  - CWindow_AddTimeoutCode
  - DecryptMessage
  - DeleteUrlCacheEntryA
  - DeleteUrlCacheEntryW
  - DeviceIoControl
  - DnsQuery_A
  - DnsQuery_UTF8
  - DnsQuery_W
  - DrawTextExA
  - DrawTextExW
  - EncryptMessage
  - EnumServicesStatusA
  - EnumServicesStatusW
  - EnumWindows
  - ExitWindowsEx
  - FindResourceA
  - FindResourceExA
  - FindResourceExW
  - FindResourceW
  - FindWindowA
  - FindWindowExA
  - FindWindowExW
  - FindWindowW
  - GetAdaptersAddresses
  - GetAdaptersInfo
  - GetAsyncKeyState
  - GetBestInterfaceEx
  - GetCursorPos
  - GetDiskFreeSpaceExW
  - GetDiskFreeSpaceW
  - GetFileVersionInfoExW
  - GetFileVersionInfoSizeExW
  - GetFileVersionInfoSizeW
  - GetFileVersionInfoW
  - GetForegroundWindow
  - GetInterfaceInfo
  - GetKeyboardState
  - GetKeyState
  - GetSystemMetrics
  - GetUserNameExA
  - GetUserNameExW
  - GetVolumeNameForVolumeMountPointW
  - GetVolumePathNamesForVolumeNameW
  - GetVolumePathNameW
  - GlobalMemoryStatus
  - GlobalMemoryStatusEx
  - HttpOpenRequestA
  - HttpOpenRequestW
  - HttpSendRequestA
  - HttpSendRequestW
  - InternetCloseHandle
  - InternetConnectA
  - InternetConnectW
  - InternetGetConnectedState
  - InternetOpenA
  - InternetOpenUrlA
  - InternetOpenUrlW
  - InternetOpenW
  - InternetQueryOptionA
  - InternetReadFile
  - InternetSetOptionA
  - InternetSetStatusCallback
  - InternetWriteFile
  - IsDebuggerPresent
  - IWbemServices_ExecMethod
  - IWbemServices_ExecMethodAsync
  - IWbemServices_ExecQuery
  - IWbemServices_ExecQueryAsync
  - LdrGetDllHandle
  - LdrGetProcedureAddress
  - LdrLoadDll
  - LdrUnloadDll
  - LoadResource
  - LoadStringA
  - LoadStringW
  - LookupAccountSidW
  - LookupPrivilegeValueW
  - MessageBoxTimeoutA
  - MessageBoxTimeoutW
  - Module32FirstW
  - Module32NextW
  - NetGetJoinInformation
  - NetShareEnum
  - NetUserGetInfo
  - NetUserGetLocalGroups
  - ObtainUserAgentString
  - OleConvertOLESTREAMToIStorage
  - OleInitialize
  - OutputDebugStringA
  - PRF
  - ReadCabinetState
  - ReadProcessMemory
  - RegEnumKeyW
  - RegisterHotKey
  - RtlAddVectoredContinueHandler
  - RtlAddVectoredExceptionHandler
  - RtlCompressBuffer
  - RtlCreateUserProcess
  - RtlCreateUserThread
  - RtlDecompressBuffer
  - RtlDecompressFragment
  - RtlDispatchException
  - RtlRemoveVectoredContinueHandler
  - RtlRemoveVectoredExceptionHandler
  - SendNotifyMessageA
  - SendNotifyMessageW
  - SetErrorMode
  - SetUnhandledExceptionFilter
  - ShellExecuteExW
  - SHGetFolderPathW
  - SHGetSpecialFolderLocation
  - SizeofResource
  - Ssl3GenerateKeyMaterial
  - system
  - TaskDialog
  - Thread32First
  - Thread32Next
  - timeGetTime
  - TransmitFile
  - UuidCreate
  - vbe6_CallByName
  - vbe6_Close
  - vbe6_CreateObject
  - vbe6_GetIDFromName
  - vbe6_GetObject
  - vbe6_Import
  - vbe6_Invoke
  - vbe6_Open
  - vbe6_Print
  - vbe6_Shell
  - vbe6_StringConcat
  - WNetGetProviderNameW
  - WriteConsoleA
  - WriteConsoleW
  - WriteProcessMemory

In addition, I modified ExitProcess and ExitThread and FreeLibraryAndExitThread
return values to be void. Were originally DECLSPEC_NORETURN.

Corrected URLDownloadToFile by changing the last argument's type from LPVOID
to LPBINDSTATUSCALLBACK

Corrected GetLastError's return value to DWORD from _Post_equals_last_error_

## Other tools

# Check if we've hooked at least all of the old API calls
```
$ python utils/process.py list-apis data/ objects/code/ sigs-old/ | awk '{print $2}' | sort -u > cmp.old
$ python utils/process.py list-apis data/ objects/code/ sigs/ | awk '{print $2}' | sort -u > cmp.new
$ comm -23 cmp.old cmp.new > cmp.missing

# cmp.missing has contents which do not appear in sigs-old/
```

```
Inside Command Prompt (Windows):
# Printing out byte values of API functions (seeing where the hooking mechanism can fit)
$ python debug.py
```

Inside Linux shell:
```
$ cd ./get-symbols

# Prints out hooked API functions used by monitor and source
# Used to check that we're not hooking any function that the monitor uses
$ python scan.py

# Converts old signatures files to new file
# Used to put all old signatures into one file (./sigs/template/sigs.rst-old-stable)
$ python old_to_new.py

    # Example
    $ cd ./sigs
    $ python old_to_new.py ../sigs-old/ ./template/sigs.rst-full > ./template/sigs.rst-old-stable

# Finds mismatches of calls in monitor debug text file
# This debug file is outputted by monitor when compiled using `$ ./make_debug.sh`
# This script is used to see if any API call has been entered but not exited
$ python match.py

    # Example
    $ python match.py monitor-debug-1054.txt
```

## Detection Logic (used by analyzer.py)

**A process needs to be tracked:**
  - CreateProcessA
  - CreateProcessW
  - CreateProcessAsUserW
  - CreateProcessAsUserA
  - CreateProcessWithLogonW
  - CreateProcessWithTokenW
  - CreateProcessInternalW

  - CreateThread
  - CreateRemoteThread
  - CreateRemoteThreadEx
  - ResumeThread
  - SetContextThread
  - QueueUserAPC

  - SendNotifyMessageA
  - SendNotifyMessageW

  - IWbemServices_ExecMethod

  - **Unsure of where this fits (from old monitor):**
    - NtMapViewOfSection

**A process terminated:**
  - TerminateProcess

**A file was created:**
  - WriteFile
  - WriteFileEx
  - WriteFileGather
  - CopyFileA
  - CopyFileW
  - CopyFileExA
  - CopyFileExW
  - CopyFileTransactedA
  - CopyFileTransactedW

  - URLDownloadToFileW

  - **Should we add?:**
    - CreateHardLinkA
    - CreateHardLinkW
    - CreateHardLinkTransactedA
    - CreateHardLinkTransactedW

**A file was moved:**
  - MoveFileA
  - MoveFileW
  - MoveFileExA
  - MoveFileExW
  - MoveFileWithProgressA
  - MoveFileWithProgressW
  - MoveFileTransactedA
  - MoveFileTransactedW
  - ReplaceFileA
  - ReplaceFileW

**A file was deleted:**
  - MoveFileWithProgressA
  - MoveFileWithProgressW
  - DeleteFileA
  - DeleteFileW
  - DeleteFileTransactedA
  - DeleteFileTransactedW
  - ReplaceFileA
  - ReplaceFileW

  - **Unsure of where this fits (from old monitor):**
    - NtSetInformationFile

**When to dump memory:**
  - ResumeThread

## Issues
**Cause `make` to error:**
  - GetConsoleFontSize
  - GetLargestConsoleWindowSize
```
error: aggregate value used where an integer was expected
         (uintptr_t) ret,
```

**Missing types:**

Had to add "#include <ws2ipdef.h>" to "/usr/share/mingw-w64/include/netioapi.h"
because of missing SOCKADDR_INET definition.

**/usr/share/mingw-w64/include/cryptxml.h**
  - error: variable or field declared void
  - Change it to "void \*pvPaddingInfo" on line 83
  - Change it to "void \*pvExtraInfo" on line 84

  - Commented out "CryptXmlDllVerifySignature" because could not find definition
    of HCRYPTXML_PROV
  - Commented out CRYPT_XML_CRYPTOGRAPHIC_INTERFACE
  - Commented out CryptXmlDllGetInterface

  - Had to move "CRYPT\_XML_KEY_VALUE" to above "CRYPT_XML_KEY_INFO_ITEM" and past
    a few variables because it wasn't ordered properly.

**/usr/share/mingw-w64/include/windns.h**
  - E.g., I added DNS_PROXY_INFORMATION_TYPE data type (and others) because "DnsGetProxyInformation()"
    required it.
  - Added DNS_ADDR_MAX_SOCKADDR_LENGTH
  - Added DNS_ADDR
  - Added DNS_ADDR_ARRAY
  - Added DNS_PROXY_COMPLETION_ROUTINE
  - Added DNS_QUERY_RESULT
  - Added DNS_QUERY_COMPLETION_ROUTINE
  - Added PDNS_QUERY_COMPLETION_ROUTINE
  - Added DNS_QUERY_REQUEST
  - Added DNS_QUERY_CANCEL
  - Added DNS_PROXY_INFORMATION_TYPE
  - Added DNS_PROXY_INFORMATION

**/usr/share/mingw-w64/include/wininet.h**
  - Commented out "#define HTTP_VERSION \_\_MINGW_NAME_AW(HTTP_VERSION)" because of
    conflicting type (HTTP_VERSION) in http.h

**/usr/share/mingw-w64/include/http.h**
  - Added ";" at end of line 459 (HTTP_PROPERTY_FLAGS)
  - Added HTTP_LOG_DATA data type
  - Added HTTP_SERVICE_CONFIG_TIMEOUT_PARAM data type
  - Added HTTP_URL_GROUP_ID and HTTP_SERVER_SESSION_ID data types
  - Copied contents of HTTP_REQUEST_V1 directly into HTTP_REQUEST_V2 because the Windows
    compiler handles this weird case. GCC does not.
    - Did same with HTTP_RESPONSE_V1 and HTTP_RESPONSE_V2
