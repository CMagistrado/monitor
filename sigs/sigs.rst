Signature::

    * Calling convention: WINAPI
    * Category: none

    
WriteConsoleA
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hConsoleOutput
    * const VOID *lpBuffer
    * DWORD nNumberOfCharsToWrite
    * LPDWORD lpNumberOfCharsWritten
    * LPVOID lpReserved


WriteConsoleW
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hConsoleOutput
    * const VOID *lpBuffer
    * DWORD nNumberOfCharsToWrite
    * LPDWORD lpNumberOfCharsWritten
    * LPVOID lpReserved


IsDebuggerPresent
=================

Signature::

    * Library: rtmpal
    * Return value: BOOL


OutputDebugStringA
==================

Signature::

    * Library: rtmpal
    * Return value: void

Parameters::

    * LPCSTR lpOutputString


SetUnhandledExceptionFilter
===========================

Signature::

    * Library: rtmpal
    * Return value: LPTOP_LEVEL_EXCEPTION_FILTER

Parameters::

    * LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter


SetErrorMode
============

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    * UINT uMode


CreateDirectoryW
================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    * LPCWSTR lpPathName
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes


DeleteFileW
===========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName


FindFirstFileExA
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPCSTR lpFileName
    * FINDEX_INFO_LEVELS fInfoLevelId
    * LPVOID lpFindFileData
    * FINDEX_SEARCH_OPS fSearchOp
    * LPVOID lpSearchFilter
    * DWORD dwAdditionalFlags


FindFirstFileExW
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPCWSTR lpFileName
    * FINDEX_INFO_LEVELS fInfoLevelId
    * LPVOID lpFindFileData
    * FINDEX_SEARCH_OPS fSearchOp
    * LPVOID lpSearchFilter
    * DWORD dwAdditionalFlags


GetDiskFreeSpaceW
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpRootPathName
    * LPDWORD lpSectorsPerCluster
    * LPDWORD lpBytesPerSector
    * LPDWORD lpNumberOfFreeClusters
    * LPDWORD lpTotalNumberOfClusters


GetDiskFreeSpaceExW
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpDirectoryName
    * PULARGE_INTEGER lpFreeBytesAvailableToCaller
    * PULARGE_INTEGER lpTotalNumberOfBytes
    * PULARGE_INTEGER lpTotalNumberOfFreeBytes


GetFileAttributesW
==================

Signature::

    * Library: rtmpal
    * Return value: DWORD

Parameters::

    * LPCWSTR lpFileName


GetFileAttributesExW
====================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName
    * GET_FILEEX_INFO_LEVELS fInfoLevelId
    * LPVOID lpFileInformation


GetFileInformationByHandle
==========================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LPBY_HANDLE_FILE_INFORMATION lpFileInformation


GetFileSize
===========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * HANDLE hFile
    * LPDWORD lpFileSizeHigh


GetFileSizeEx
=============

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * PLARGE_INTEGER lpFileSize


GetFileType
===========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * HANDLE hFile


GetShortPathNameW
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpszLongPath
    * LPWSTR lpszShortPath
    * DWORD cchBuffer


GetVolumePathNameW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpszFileName
    * LPWSTR lpszVolumePathName
    * DWORD cchBufferLength


RemoveDirectoryA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpPathName


RemoveDirectoryW
================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    * LPCWSTR lpPathName


SetEndOfFile
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile


SetFileAttributesW
==================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName
    * DWORD dwFileAttributes


SetFileInformationByHandle
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * FILE_INFO_BY_HANDLE_CLASS FileInformationClass
    * LPVOID lpFileInformation
    * DWORD dwBufferSize


SetFilePointer
==============

Signature::

    * Library: rtmpal
    * Return value: DWORD

Parameters::

    * HANDLE hFile
    * LONG lDistanceToMove
    * PLONG lpDistanceToMoveHigh
    * DWORD dwMoveMethod


SetFilePointerEx
================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LARGE_INTEGER liDistanceToMove
    * PLARGE_INTEGER lpNewFilePointer
    * DWORD dwMoveMethod


SetFileTime
===========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * const FILETIME *lpCreationTime
    * const FILETIME *lpLastAccessTime
    * const FILETIME *lpLastWriteTime


GetTempPathW
============

Signature::

    * Library: rtmpal
    * Return value: DWORD

Parameters::

    * DWORD nBufferLength
    * LPWSTR lpBuffer


GetVolumeNameForVolumeMountPointW
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpszVolumeMountPoint
    * LPWSTR lpszVolumeName
    * DWORD cchBufferLength


GetVolumePathNamesForVolumeNameW
================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpszVolumeName
    * LPWCH lpszVolumePathNames
    * DWORD cchBufferLength
    * PDWORD lpcchReturnLength


DeviceIoControl
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hDevice
    * DWORD dwIoControlCode
    * LPVOID lpInBuffer
    * DWORD nInBufferSize
    * LPVOID lpOutBuffer
    * DWORD nOutBufferSize
    * LPDWORD lpBytesReturned
    * LPOVERLAPPED lpOverlapped


FindResourceExW
===============

Signature::

    * Library: kernel32
    * Return value: HRSRC

Parameters::

    * HMODULE hModule
    * LPCWSTR lpType
    * LPCWSTR lpName
    * WORD wLanguage


LoadResource
============

Signature::

    * Library: kernel32
    * Return value: HGLOBAL

Parameters::

    * HMODULE hModule
    * HRSRC hResInfo


SizeofResource
==============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * HMODULE hModule
    * HRSRC hResInfo


ReadProcessMemory
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hProcess
    * LPCVOID lpBaseAddress
    * LPVOID lpBuffer
    * SIZE_T nSize
    * SIZE_T *lpNumberOfBytesRead


WriteProcessMemory
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hProcess
    * LPVOID lpBaseAddress
    * LPCVOID lpBuffer
    * SIZE_T nSize
    * SIZE_T *lpNumberOfBytesWritten


SearchPathW
===========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpPath
    * LPCWSTR lpFileName
    * LPCWSTR lpExtension
    * DWORD nBufferLength
    * LPWSTR lpBuffer
    * LPWSTR *lpFilePart


CreateThread
============

Signature::

    * Library: rtmpal
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpThreadAttributes
    * SIZE_T dwStackSize
    * LPTHREAD_START_ROUTINE lpStartAddress
    * LPVOID lpParameter
    * DWORD dwCreationFlags
    * LPDWORD lpThreadId


CreateRemoteThread
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * HANDLE hProcess
    * LPSECURITY_ATTRIBUTES lpThreadAttributes
    * SIZE_T dwStackSize
    * LPTHREAD_START_ROUTINE lpStartAddress
    * LPVOID lpParameter
    * DWORD dwCreationFlags
    * LPDWORD lpThreadId


CreateRemoteThreadEx
====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * HANDLE hProcess
    * LPSECURITY_ATTRIBUTES lpThreadAttributes
    * SIZE_T dwStackSize
    * LPTHREAD_START_ROUTINE lpStartAddress
    * LPVOID lpParameter
    * DWORD dwCreationFlags
    * LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
    * LPDWORD lpThreadId


GlobalMemoryStatusEx
====================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    * LPMEMORYSTATUSEX lpBuffer


GetSystemTime
=============

Signature::

    * Library: rtmpal
    * Return value: void

Parameters::

    * LPSYSTEMTIME lpSystemTime


GetSystemTimeAsFileTime
=======================

Signature::

    * Library: rtmpal
    * Return value: void

Parameters::

    * LPFILETIME lpSystemTimeAsFileTime


GetLocalTime
============

Signature::

    * Library: rtmpal
    * Return value: void

Parameters::

    * LPSYSTEMTIME lpSystemTime


GetSystemInfo
=============

Signature::

    * Library: rtmpal
    * Return value: void

Parameters::

    * LPSYSTEM_INFO lpSystemInfo


GetTickCount
============

Signature::

    * Library: rtmpal
    * Return value: DWORD


GetSystemDirectoryA
===================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    * LPSTR lpBuffer
    * UINT uSize


GetSystemDirectoryW
===================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    * LPWSTR lpBuffer
    * UINT uSize


GetSystemWindowsDirectoryA
==========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    * LPSTR lpBuffer
    * UINT uSize


GetSystemWindowsDirectoryW
==========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    * LPWSTR lpBuffer
    * UINT uSize


GetNativeSystemInfo
===================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    * LPSYSTEM_INFO lpSystemInfo


GetTimeZoneInformation
======================

Signature::

    * Library: rtmpal
    * Return value: DWORD

Parameters::

    * LPTIME_ZONE_INFORMATION lpTimeZoneInformation


GlobalMemoryStatus
==================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    * LPMEMORYSTATUS lpBuffer


FindResourceA
=============

Signature::

    * Library: kernel32
    * Return value: HRSRC

Parameters::

    * HMODULE hModule
    * LPCSTR lpName
    * LPCSTR lpType


FindResourceW
=============

Signature::

    * Library: kernel32
    * Return value: HRSRC

Parameters::

    * HMODULE hModule
    * LPCWSTR lpName
    * LPCWSTR lpType


FindResourceExA
===============

Signature::

    * Library: kernel32
    * Return value: HRSRC

Parameters::

    * HMODULE hModule
    * LPCSTR lpType
    * LPCSTR lpName
    * WORD wLanguage


CreateDirectoryExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpTemplateDirectory
    * LPCWSTR lpNewDirectory
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes


CopyFileA
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpExistingFileName
    * LPCSTR lpNewFileName
    * BOOL bFailIfExists


CopyFileW
=========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    * LPCWSTR lpExistingFileName
    * LPCWSTR lpNewFileName
    * BOOL bFailIfExists


CopyFileExW
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpExistingFileName
    * LPCWSTR lpNewFileName
    * LPPROGRESS_ROUTINE lpProgressRoutine
    * LPVOID lpData
    * LPBOOL pbCancel
    * DWORD dwCopyFlags


MoveFileWithProgressW
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpExistingFileName
    * LPCWSTR lpNewFileName
    * LPPROGRESS_ROUTINE lpProgressRoutine
    * LPVOID lpData
    * DWORD dwFlags


GetComputerNameA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPSTR lpBuffer
    * LPDWORD nSize


GetComputerNameW
================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    * LPWSTR lpBuffer
    * LPDWORD nSize


CreateActCtxW
=============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * PCACTCTXW pActCtx


GetFileInformationByHandleEx
============================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * FILE_INFO_BY_HANDLE_CLASS FileInformationClass
    * LPVOID lpFileInformation
    * DWORD dwBufferSize


