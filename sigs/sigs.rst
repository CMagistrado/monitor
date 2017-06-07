Signature::

    * Calling convention: WINAPI
    * Category: none


ClearCommBreak
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile


ClearCommError
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPDWORD lpErrors
    ** LPCOMSTAT lpStat


SetupComm
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** DWORD dwInQueue
    ** DWORD dwOutQueue


EscapeCommFunction
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** DWORD dwFunc


GetCommConfig
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hCommDev
    ** LPCOMMCONFIG lpCC
    ** LPDWORD lpdwSize


GetCommMask
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPDWORD lpEvtMask


GetCommModemStatus
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPDWORD lpModemStat


GetCommProperties
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPCOMMPROP lpCommProp


GetCommState
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPDCB lpDCB


GetCommTimeouts
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPCOMMTIMEOUTS lpCommTimeouts


PurgeComm
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** DWORD dwFlags


SetCommBreak
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile


SetCommConfig
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hCommDev
    ** LPCOMMCONFIG lpCC
    ** DWORD dwSize


SetCommMask
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** DWORD dwEvtMask


SetCommState
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPDCB lpDCB


SetCommTimeouts
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPCOMMTIMEOUTS lpCommTimeouts


TransmitCommChar
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** char cChar


WaitCommEvent
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPDWORD lpEvtMask
    ** LPOVERLAPPED lpOverlapped


AllocConsole
============

Signature::

    * Library: kernel32
    * Return value: BOOL


GetConsoleCP
============

Signature::

    * Library: kernel32
    * Return value: UINT


GetConsoleMode
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleHandle
    ** LPDWORD lpMode


GetConsoleOutputCP
==================

Signature::

    * Library: kernel32
    * Return value: UINT


GetNumberOfConsoleInputEvents
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleInput
    ** LPDWORD lpNumberOfEvents


PeekConsoleInputA
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleInput
    ** PINPUT_RECORD lpBuffer
    ** DWORD nLength
    ** LPDWORD lpNumberOfEventsRead


ReadConsoleA
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleInput
    ** LPVOID lpBuffer
    ** DWORD nNumberOfCharsToRead
    ** LPDWORD lpNumberOfCharsRead
    ** PCONSOLE_READCONSOLE_CONTROL pInputControl


ReadConsoleW
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleInput
    ** LPVOID lpBuffer
    ** DWORD nNumberOfCharsToRead
    ** LPDWORD lpNumberOfCharsRead
    ** PCONSOLE_READCONSOLE_CONTROL pInputControl


ReadConsoleInputA
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleInput
    ** PINPUT_RECORD lpBuffer
    ** DWORD nLength
    ** LPDWORD lpNumberOfEventsRead


ReadConsoleInputW
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleInput
    ** PINPUT_RECORD lpBuffer
    ** DWORD nLength
    ** LPDWORD lpNumberOfEventsRead


SetConsoleCtrlHandler
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PHANDLER_ROUTINE HandlerRoutine
    ** BOOL Add


SetConsoleMode
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleHandle
    ** DWORD dwMode


WriteConsoleA
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** void *lpBuffer
    ** DWORD nNumberOfCharsToWrite
    ** LPDWORD lpNumberOfCharsWritten
    ** LPVOID lpReserved


WriteConsoleW
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** void *lpBuffer
    ** DWORD nNumberOfCharsToWrite
    ** LPDWORD lpNumberOfCharsWritten
    ** LPVOID lpReserved


GetDateFormatA
==============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwFlags
    ** SYSTEMTIME *lpDate
    ** LPCSTR lpFormat
    ** LPSTR lpDateStr
    ** int cchDate


GetDateFormatW
==============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwFlags
    ** SYSTEMTIME *lpDate
    ** LPCWSTR lpFormat
    ** LPWSTR lpDateStr
    ** int cchDate


GetTimeFormatA
==============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwFlags
    ** SYSTEMTIME *lpTime
    ** LPCSTR lpFormat
    ** LPSTR lpTimeStr
    ** int cchTime


GetTimeFormatW
==============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwFlags
    ** SYSTEMTIME *lpTime
    ** LPCWSTR lpFormat
    ** LPWSTR lpTimeStr
    ** int cchTime


GetTimeFormatEx
===============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCWSTR lpLocaleName
    ** DWORD dwFlags
    ** SYSTEMTIME *lpTime
    ** LPCWSTR lpFormat
    ** LPWSTR lpTimeStr
    ** int cchTime


GetDateFormatEx
===============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCWSTR lpLocaleName
    ** DWORD dwFlags
    ** SYSTEMTIME *lpDate
    ** LPCWSTR lpFormat
    ** LPWSTR lpDateStr
    ** int cchDate
    ** LPCWSTR lpCalendar


IsDebuggerPresent
=================

Signature::

    * Library: kernel32
    * Return value: BOOL


DebugBreak
==========

Signature::

    * Library: kernel32
    * Return value: void


OutputDebugStringA
==================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPCSTR lpOutputString


OutputDebugStringW
==================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPCWSTR lpOutputString


ContinueDebugEvent
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwProcessId
    ** DWORD dwThreadId
    ** DWORD dwContinueStatus


WaitForDebugEvent
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPDEBUG_EVENT lpDebugEvent
    ** DWORD dwMilliseconds


DebugActiveProcess
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwProcessId


DebugActiveProcessStop
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwProcessId


CheckRemoteDebuggerPresent
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PBOOL pbDebuggerPresent


RaiseException
==============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** DWORD dwExceptionCode
    ** DWORD dwExceptionFlags
    ** DWORD nNumberOfArguments
    ** ULONG_PTR *lpArguments


UnhandledExceptionFilter
========================

Signature::

    * Library: kernel32
    * Return value: LONG

Parameters::

    ** struct _EXCEPTION_POINTERS *ExceptionInfo


SetUnhandledExceptionFilter
===========================

Signature::

    * Library: kernel32
    * Return value: LPTOP_LEVEL_EXCEPTION_FILTER

Parameters::

    ** LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter


GetLastError
============

Signature::

    * Library: kernel32
    * Return value: DWORD


SetLastError
============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** DWORD dwErrCode


GetErrorMode
============

Signature::

    * Library: kernel32
    * Return value: UINT


SetErrorMode
============

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** UINT uMode


AddVectoredExceptionHandler
===========================

Signature::

    * Library: kernel32
    * Return value: PVOID

Parameters::

    ** ULONG First
    ** PVECTORED_EXCEPTION_HANDLER Handler


RemoveVectoredExceptionHandler
==============================

Signature::

    * Library: kernel32
    * Return value: ULONG

Parameters::

    ** PVOID Handle


AddVectoredContinueHandler
==========================

Signature::

    * Library: kernel32
    * Return value: PVOID

Parameters::

    ** ULONG First
    ** PVECTORED_EXCEPTION_HANDLER Handler


RemoveVectoredContinueHandler
=============================

Signature::

    * Library: kernel32
    * Return value: ULONG

Parameters::

    ** PVOID Handle


RestoreLastError
================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** DWORD dwErrCode


FlsAlloc
========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** PFLS_CALLBACK_FUNCTION lpCallback


FlsGetValue
===========

Signature::

    * Library: kernel32
    * Return value: PVOID

Parameters::

    ** DWORD dwFlsIndex


FlsSetValue
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlsIndex
    ** PVOID lpFlsData


FlsFree
=======

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlsIndex


IsThreadAFiber
==============

Signature::

    * Library: kernel32
    * Return value: BOOL


CompareFileTime
===============

Signature::

    * Library: kernel32
    * Return value: LONG

Parameters::

    ** FILETIME *lpFileTime1
    ** FILETIME *lpFileTime2


CreateDirectoryA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpPathName
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateDirectoryW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpPathName
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateFileA
===========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCSTR lpFileName
    ** DWORD dwDesiredAccess
    ** DWORD dwShareMode
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** DWORD dwCreationDisposition
    ** DWORD dwFlagsAndAttributes
    ** HANDLE hTemplateFile


CreateFileW
===========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD dwDesiredAccess
    ** DWORD dwShareMode
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** DWORD dwCreationDisposition
    ** DWORD dwFlagsAndAttributes
    ** HANDLE hTemplateFile


DefineDosDeviceW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** LPCWSTR lpDeviceName
    ** LPCWSTR lpTargetPath


DeleteFileA
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName


DeleteFileW
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName


DeleteVolumeMountPointW
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszVolumeMountPoint


FileTimeToLocalFileTime
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** FILETIME *lpFileTime
    ** LPFILETIME lpLocalFileTime


FindClose
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindFile


FindCloseChangeNotification
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hChangeHandle


FindFirstChangeNotificationA
============================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCSTR lpPathName
    ** BOOL bWatchSubtree
    ** DWORD dwNotifyFilter


FindFirstChangeNotificationW
============================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpPathName
    ** BOOL bWatchSubtree
    ** DWORD dwNotifyFilter


FindFirstFileA
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCSTR lpFileName
    ** LPWIN32_FIND_DATAA lpFindFileData


FindFirstFileW
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpFileName
    ** LPWIN32_FIND_DATAW lpFindFileData


FindFirstFileExA
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCSTR lpFileName
    ** FINDEX_INFO_LEVELS fInfoLevelId
    ** LPVOID lpFindFileData
    ** FINDEX_SEARCH_OPS fSearchOp
    ** LPVOID lpSearchFilter
    ** DWORD dwAdditionalFlags


FindFirstFileExW
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpFileName
    ** FINDEX_INFO_LEVELS fInfoLevelId
    ** LPVOID lpFindFileData
    ** FINDEX_SEARCH_OPS fSearchOp
    ** LPVOID lpSearchFilter
    ** DWORD dwAdditionalFlags


FindFirstVolumeW
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPWSTR lpszVolumeName
    ** DWORD cchBufferLength


FindNextChangeNotification
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hChangeHandle


FindNextFileA
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindFile
    ** LPWIN32_FIND_DATAA lpFindFileData


FindNextFileW
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindFile
    ** LPWIN32_FIND_DATAW lpFindFileData


FindNextVolumeW
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindVolume
    ** LPWSTR lpszVolumeName
    ** DWORD cchBufferLength


FindVolumeClose
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindVolume


FlushFileBuffers
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile


GetDiskFreeSpaceA
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpRootPathName
    ** LPDWORD lpSectorsPerCluster
    ** LPDWORD lpBytesPerSector
    ** LPDWORD lpNumberOfFreeClusters
    ** LPDWORD lpTotalNumberOfClusters


GetDiskFreeSpaceW
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpRootPathName
    ** LPDWORD lpSectorsPerCluster
    ** LPDWORD lpBytesPerSector
    ** LPDWORD lpNumberOfFreeClusters
    ** LPDWORD lpTotalNumberOfClusters


GetDiskFreeSpaceExA
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpDirectoryName
    ** PULARGE_INTEGER lpFreeBytesAvailableToCaller
    ** PULARGE_INTEGER lpTotalNumberOfBytes
    ** PULARGE_INTEGER lpTotalNumberOfFreeBytes


GetDiskFreeSpaceExW
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpDirectoryName
    ** PULARGE_INTEGER lpFreeBytesAvailableToCaller
    ** PULARGE_INTEGER lpTotalNumberOfBytes
    ** PULARGE_INTEGER lpTotalNumberOfFreeBytes


GetDriveTypeA
=============

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPCSTR lpRootPathName


GetDriveTypeW
=============

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPCWSTR lpRootPathName


GetFileAttributesA
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpFileName


GetFileAttributesW
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName


GetFileAttributesExA
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** GET_FILEEX_INFO_LEVELS fInfoLevelId
    ** LPVOID lpFileInformation


GetFileAttributesExW
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** GET_FILEEX_INFO_LEVELS fInfoLevelId
    ** LPVOID lpFileInformation


GetFileInformationByHandle
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPBY_HANDLE_FILE_INFORMATION lpFileInformation


GetFileSize
===========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hFile
    ** LPDWORD lpFileSizeHigh


GetFileSizeEx
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** PLARGE_INTEGER lpFileSize


GetFileTime
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPFILETIME lpCreationTime
    ** LPFILETIME lpLastAccessTime
    ** LPFILETIME lpLastWriteTime


GetFileType
===========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hFile


GetFinalPathNameByHandleA
=========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hFile
    ** LPSTR lpszFilePath
    ** DWORD cchFilePath
    ** DWORD dwFlags


GetFinalPathNameByHandleW
=========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hFile
    ** LPWSTR lpszFilePath
    ** DWORD cchFilePath
    ** DWORD dwFlags


GetFullPathNameA
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpFileName
    ** DWORD nBufferLength
    ** LPSTR lpBuffer
    ** LPSTR *lpFilePart


GetFullPathNameW
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD nBufferLength
    ** LPWSTR lpBuffer
    ** LPWSTR *lpFilePart


GetLogicalDrives
================

Signature::

    * Library: kernel32
    * Return value: DWORD


GetLogicalDriveStringsW
=======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPWSTR lpBuffer


GetLongPathNameA
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpszShortPath
    ** LPSTR lpszLongPath
    ** DWORD cchBuffer


GetLongPathNameW
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpszShortPath
    ** LPWSTR lpszLongPath
    ** DWORD cchBuffer


GetShortPathNameW
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpszLongPath
    ** LPWSTR lpszShortPath
    ** DWORD cchBuffer


GetTempFileNameW
================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPCWSTR lpPathName
    ** LPCWSTR lpPrefixString
    ** UINT uUnique
    ** LPWSTR lpTempFileName


GetVolumeInformationByHandleW
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPWSTR lpVolumeNameBuffer
    ** DWORD nVolumeNameSize
    ** LPDWORD lpVolumeSerialNumber
    ** LPDWORD lpMaximumComponentLength
    ** LPDWORD lpFileSystemFlags
    ** LPWSTR lpFileSystemNameBuffer
    ** DWORD nFileSystemNameSize


GetVolumeInformationW
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpRootPathName
    ** LPWSTR lpVolumeNameBuffer
    ** DWORD nVolumeNameSize
    ** LPDWORD lpVolumeSerialNumber
    ** LPDWORD lpMaximumComponentLength
    ** LPDWORD lpFileSystemFlags
    ** LPWSTR lpFileSystemNameBuffer
    ** DWORD nFileSystemNameSize


GetVolumePathNameW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszFileName
    ** LPWSTR lpszVolumePathName
    ** DWORD cchBufferLength


LocalFileTimeToFileTime
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** FILETIME *lpLocalFileTime
    ** LPFILETIME lpFileTime


LockFile
========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** DWORD dwFileOffsetLow
    ** DWORD dwFileOffsetHigh
    ** DWORD nNumberOfBytesToLockLow
    ** DWORD nNumberOfBytesToLockHigh


LockFileEx
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** DWORD dwFlags
    ** DWORD dwReserved
    ** DWORD nNumberOfBytesToLockLow
    ** DWORD nNumberOfBytesToLockHigh
    ** LPOVERLAPPED lpOverlapped


QueryDosDeviceW
===============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpDeviceName
    ** LPWSTR lpTargetPath
    ** DWORD ucchMax


ReadFile
========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPVOID lpBuffer
    ** DWORD nNumberOfBytesToRead
    ** LPDWORD lpNumberOfBytesRead
    ** LPOVERLAPPED lpOverlapped


ReadFileEx
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPVOID lpBuffer
    ** DWORD nNumberOfBytesToRead
    ** LPOVERLAPPED lpOverlapped
    ** LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


ReadFileScatter
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** FILE_SEGMENT_ELEMENT aSegmentArray[]
    ** DWORD nNumberOfBytesToRead
    ** LPDWORD lpReserved
    ** LPOVERLAPPED lpOverlapped


RemoveDirectoryA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpPathName


RemoveDirectoryW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpPathName


SetEndOfFile
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile


SetFileAttributesA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** DWORD dwFileAttributes


SetFileAttributesW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD dwFileAttributes


SetFileInformationByHandle
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** FILE_INFO_BY_HANDLE_CLASS FileInformationClass
    ** LPVOID lpFileInformation
    ** DWORD dwBufferSize


SetFilePointer
==============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hFile
    ** LONG lDistanceToMove
    ** PLONG lpDistanceToMoveHigh
    ** DWORD dwMoveMethod


SetFilePointerEx
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LARGE_INTEGER liDistanceToMove
    ** PLARGE_INTEGER lpNewFilePointer
    ** DWORD dwMoveMethod


SetFileTime
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** FILETIME *lpCreationTime
    ** FILETIME *lpLastAccessTime
    ** FILETIME *lpLastWriteTime


SetFileValidData
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LONGLONG ValidDataLength


UnlockFile
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** DWORD dwFileOffsetLow
    ** DWORD dwFileOffsetHigh
    ** DWORD nNumberOfBytesToUnlockLow
    ** DWORD nNumberOfBytesToUnlockHigh


UnlockFileEx
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** DWORD dwReserved
    ** DWORD nNumberOfBytesToUnlockLow
    ** DWORD nNumberOfBytesToUnlockHigh
    ** LPOVERLAPPED lpOverlapped


WriteFile
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPCVOID lpBuffer
    ** DWORD nNumberOfBytesToWrite
    ** LPDWORD lpNumberOfBytesWritten
    ** LPOVERLAPPED lpOverlapped


WriteFileEx
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPCVOID lpBuffer
    ** DWORD nNumberOfBytesToWrite
    ** LPOVERLAPPED lpOverlapped
    ** LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


WriteFileGather
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** FILE_SEGMENT_ELEMENT aSegmentArray[]
    ** DWORD nNumberOfBytesToWrite
    ** LPDWORD lpReserved
    ** LPOVERLAPPED lpOverlapped


GetTempPathW
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPWSTR lpBuffer


GetVolumeNameForVolumeMountPointW
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszVolumeMountPoint
    ** LPWSTR lpszVolumeName
    ** DWORD cchBufferLength


GetVolumePathNamesForVolumeNameW
================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszVolumeName
    ** LPWCH lpszVolumePathNames
    ** DWORD cchBufferLength
    ** PDWORD lpcchReturnLength


CreateFile2
===========

Signature::

    * Library: 
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD dwDesiredAccess
    ** DWORD dwShareMode
    ** DWORD dwCreationDisposition
    ** LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams


SetFileIoOverlappedRange
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE FileHandle
    ** PUCHAR OverlappedRangeStart
    ** ULONG Length


GetCompressedFileSizeA
======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpFileName
    ** LPDWORD lpFileSizeHigh


GetCompressedFileSizeW
======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** LPDWORD lpFileSizeHigh


CloseHandle
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hObject


DuplicateHandle
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSourceProcessHandle
    ** HANDLE hSourceHandle
    ** HANDLE hTargetProcessHandle
    ** LPHANDLE lpTargetHandle
    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** DWORD dwOptions


GetHandleInformation
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hObject
    ** LPDWORD lpdwFlags


SetHandleInformation
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hObject
    ** DWORD dwMask
    ** DWORD dwFlags


HeapCreate
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD flOptions
    ** SIZE_T dwInitialSize
    ** SIZE_T dwMaximumSize


HeapDestroy
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hHeap


HeapAlloc
=========

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** HANDLE hHeap
    ** DWORD dwFlags
    ** SIZE_T dwBytes


HeapReAlloc
===========

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** HANDLE hHeap
    ** DWORD dwFlags
    ** LPVOID lpMem
    ** SIZE_T dwBytes


HeapFree
========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hHeap
    ** DWORD dwFlags
    ** LPVOID lpMem


HeapSize
========

Signature::

    * Library: kernel32
    * Return value: SIZE_T

Parameters::

    ** HANDLE hHeap
    ** DWORD dwFlags
    ** LPCVOID lpMem


HeapValidate
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hHeap
    ** DWORD dwFlags
    ** LPCVOID lpMem


HeapCompact
===========

Signature::

    * Library: kernel32
    * Return value: SIZE_T

Parameters::

    ** HANDLE hHeap
    ** DWORD dwFlags


GetProcessHeap
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE


GetProcessHeaps
===============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD NumberOfHeaps
    ** PHANDLE ProcessHeaps


HeapLock
========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hHeap


HeapUnlock
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hHeap


HeapWalk
========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hHeap
    ** LPPROCESS_HEAP_ENTRY lpEntry


HeapSetInformation
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE HeapHandle
    ** HEAP_INFORMATION_CLASS HeapInformationClass
    ** PVOID HeapInformation
    ** SIZE_T HeapInformationLength


HeapQueryInformation
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE HeapHandle
    ** HEAP_INFORMATION_CLASS HeapInformationClass
    ** PVOID HeapInformation
    ** SIZE_T HeapInformationLength
    ** PSIZE_T ReturnLength


InitializeSListHead
===================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PSLIST_HEADER ListHead


InterlockedPopEntrySList
========================

Signature::

    * Library: kernel32
    * Return value: PSLIST_ENTRY

Parameters::

    ** PSLIST_HEADER ListHead


InterlockedPushEntrySList
=========================

Signature::

    * Library: kernel32
    * Return value: PSLIST_ENTRY

Parameters::

    ** PSLIST_HEADER ListHead
    ** PSLIST_ENTRY ListEntry


InterlockedFlushSList
=====================

Signature::

    * Library: kernel32
    * Return value: PSLIST_ENTRY

Parameters::

    ** PSLIST_HEADER ListHead


QueryDepthSList
===============

Signature::

    * Library: kernel32
    * Return value: USHORT

Parameters::

    ** PSLIST_HEADER ListHead


GetOverlappedResult
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPOVERLAPPED lpOverlapped
    ** LPDWORD lpNumberOfBytesTransferred
    ** BOOL bWait


CreateIoCompletionPort
======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** HANDLE FileHandle
    ** HANDLE ExistingCompletionPort
    ** ULONG_PTR CompletionKey
    ** DWORD NumberOfConcurrentThreads


GetQueuedCompletionStatus
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE CompletionPort
    ** LPDWORD lpNumberOfBytesTransferred
    ** PULONG_PTR lpCompletionKey
    ** LPOVERLAPPED *lpOverlapped
    ** DWORD dwMilliseconds


GetQueuedCompletionStatusEx
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE CompletionPort
    ** LPOVERLAPPED_ENTRY lpCompletionPortEntries
    ** ULONG ulCount
    ** PULONG ulNumEntriesRemoved
    ** DWORD dwMilliseconds
    ** BOOL fAlertable


PostQueuedCompletionStatus
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE CompletionPort
    ** DWORD dwNumberOfBytesTransferred
    ** ULONG_PTR dwCompletionKey
    ** LPOVERLAPPED lpOverlapped


DeviceIoControl
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hDevice
    ** DWORD dwIoControlCode
    ** LPVOID lpInBuffer
    ** DWORD nInBufferSize
    ** LPVOID lpOutBuffer
    ** DWORD nOutBufferSize
    ** LPDWORD lpBytesReturned
    ** LPOVERLAPPED lpOverlapped


CancelIoEx
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPOVERLAPPED lpOverlapped


CancelIo
========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile


CancelSynchronousIo
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread


IsProcessInJob
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE ProcessHandle
    ** HANDLE JobHandle
    ** PBOOL Result


DisableThreadLibraryCalls
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hLibModule


FindResourceExW
===============

Signature::

    * Library: kernel32
    * Return value: HRSRC

Parameters::

    ** HMODULE hModule
    ** LPCWSTR lpType
    ** LPCWSTR lpName
    ** WORD wLanguage


FindStringOrdinal
=================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** DWORD dwFindStringOrdinalFlags
    ** LPCWSTR lpStringSource
    ** int cchSource
    ** LPCWSTR lpStringValue
    ** int cchValue
    ** BOOL bIgnoreCase


FreeLibrary
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hLibModule


FreeLibraryAndExitThread
========================

Signature::

    * Library: kernel32
    * Return value: DECLSPEC_NORETURN

Parameters::

    ** HMODULE hLibModule
    ** DWORD dwExitCode


FreeResource
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HGLOBAL hResData


GetModuleFileNameA
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HMODULE hModule
    ** LPSTR lpFilename
    ** DWORD nSize


GetModuleFileNameW
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HMODULE hModule
    ** LPWSTR lpFilename
    ** DWORD nSize


GetModuleHandleA
================

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    ** LPCSTR lpModuleName


GetModuleHandleW
================

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    ** LPCWSTR lpModuleName


GetModuleHandleExA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** LPCSTR lpModuleName
    ** HMODULE *phModule


GetModuleHandleExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** LPCWSTR lpModuleName
    ** HMODULE *phModule


GetProcAddress
==============

Signature::

    * Library: kernel32
    * Return value: FARPROC

Parameters::

    ** HMODULE hModule
    ** LPCSTR lpProcName


LoadLibraryExA
==============

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    ** LPCSTR lpLibFileName
    ** HANDLE hFile
    ** DWORD dwFlags


LoadLibraryExW
==============

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    ** LPCWSTR lpLibFileName
    ** HANDLE hFile
    ** DWORD dwFlags


LoadResource
============

Signature::

    * Library: kernel32
    * Return value: HGLOBAL

Parameters::

    ** HMODULE hModule
    ** HRSRC hResInfo


LockResource
============

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** HGLOBAL hResData


SizeofResource
==============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HMODULE hModule
    ** HRSRC hResInfo


AddDllDirectory
===============

Signature::

    * Library: kernel32
    * Return value: DLL_DIRECTORY_COOKIE

Parameters::

    ** PCWSTR NewDirectory


RemoveDllDirectory
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DLL_DIRECTORY_COOKIE Cookie


SetDefaultDllDirectories
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD DirectoryFlags


EnumResourceLanguagesExA
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hModule
    ** LPCSTR lpType
    ** LPCSTR lpName
    ** ENUMRESLANGPROCA lpEnumFunc
    ** LONG_PTR lParam
    ** DWORD dwFlags
    ** LANGID LangId


EnumResourceLanguagesExW
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hModule
    ** LPCWSTR lpType
    ** LPCWSTR lpName
    ** ENUMRESLANGPROCW lpEnumFunc
    ** LONG_PTR lParam
    ** DWORD dwFlags
    ** LANGID LangId


EnumResourceNamesExA
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hModule
    ** LPCSTR lpType
    ** ENUMRESNAMEPROCA lpEnumFunc
    ** LONG_PTR lParam
    ** DWORD dwFlags
    ** LANGID LangId


EnumResourceNamesExW
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hModule
    ** LPCWSTR lpType
    ** ENUMRESNAMEPROCW lpEnumFunc
    ** LONG_PTR lParam
    ** DWORD dwFlags
    ** LANGID LangId


EnumResourceTypesExA
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hModule
    ** ENUMRESTYPEPROCA lpEnumFunc
    ** LONG_PTR lParam
    ** DWORD dwFlags
    ** LANGID LangId


EnumResourceTypesExW
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hModule
    ** ENUMRESTYPEPROCW lpEnumFunc
    ** LONG_PTR lParam
    ** DWORD dwFlags
    ** LANGID LangId


VirtualAlloc
============

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** LPVOID lpAddress
    ** SIZE_T dwSize
    ** DWORD flAllocationType
    ** DWORD flProtect


VirtualFree
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPVOID lpAddress
    ** SIZE_T dwSize
    ** DWORD dwFreeType


VirtualProtect
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPVOID lpAddress
    ** SIZE_T dwSize
    ** DWORD flNewProtect
    ** PDWORD lpflOldProtect


VirtualQuery
============

Signature::

    * Library: kernel32
    * Return value: SIZE_T

Parameters::

    ** LPCVOID lpAddress
    ** PMEMORY_BASIC_INFORMATION lpBuffer
    ** SIZE_T dwLength


VirtualAllocEx
==============

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** HANDLE hProcess
    ** LPVOID lpAddress
    ** SIZE_T dwSize
    ** DWORD flAllocationType
    ** DWORD flProtect


VirtualFreeEx
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** LPVOID lpAddress
    ** SIZE_T dwSize
    ** DWORD dwFreeType


VirtualProtectEx
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** LPVOID lpAddress
    ** SIZE_T dwSize
    ** DWORD flNewProtect
    ** PDWORD lpflOldProtect


VirtualQueryEx
==============

Signature::

    * Library: kernel32
    * Return value: SIZE_T

Parameters::

    ** HANDLE hProcess
    ** LPCVOID lpAddress
    ** PMEMORY_BASIC_INFORMATION lpBuffer
    ** SIZE_T dwLength


ReadProcessMemory
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** LPCVOID lpBaseAddress
    ** LPVOID lpBuffer
    ** SIZE_T nSize
    ** SIZE_T *lpNumberOfBytesRead


WriteProcessMemory
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** LPVOID lpBaseAddress
    ** LPCVOID lpBuffer
    ** SIZE_T nSize
    ** SIZE_T *lpNumberOfBytesWritten


CreateFileMappingW
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** HANDLE hFile
    ** LPSECURITY_ATTRIBUTES lpFileMappingAttributes
    ** DWORD flProtect
    ** DWORD dwMaximumSizeHigh
    ** DWORD dwMaximumSizeLow
    ** LPCWSTR lpName


OpenFileMappingW
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCWSTR lpName


MapViewOfFile
=============

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** HANDLE hFileMappingObject
    ** DWORD dwDesiredAccess
    ** DWORD dwFileOffsetHigh
    ** DWORD dwFileOffsetLow
    ** SIZE_T dwNumberOfBytesToMap


MapViewOfFileEx
===============

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** HANDLE hFileMappingObject
    ** DWORD dwDesiredAccess
    ** DWORD dwFileOffsetHigh
    ** DWORD dwFileOffsetLow
    ** SIZE_T dwNumberOfBytesToMap
    ** LPVOID lpBaseAddress


FlushViewOfFile
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCVOID lpBaseAddress
    ** SIZE_T dwNumberOfBytesToFlush


UnmapViewOfFile
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCVOID lpBaseAddress


GetLargePageMinimum
===================

Signature::

    * Library: kernel32
    * Return value: SIZE_T


GetProcessWorkingSetSizeEx
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PSIZE_T lpMinimumWorkingSetSize
    ** PSIZE_T lpMaximumWorkingSetSize
    ** PDWORD Flags


SetProcessWorkingSetSizeEx
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** SIZE_T dwMinimumWorkingSetSize
    ** SIZE_T dwMaximumWorkingSetSize
    ** DWORD Flags


VirtualLock
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPVOID lpAddress
    ** SIZE_T dwSize


VirtualUnlock
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPVOID lpAddress
    ** SIZE_T dwSize


GetWriteWatch
=============

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** DWORD dwFlags
    ** PVOID lpBaseAddress
    ** SIZE_T dwRegionSize
    ** PVOID *lpAddresses
    ** ULONG_PTR *lpdwCount
    ** LPDWORD lpdwGranularity


ResetWriteWatch
===============

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPVOID lpBaseAddress
    ** SIZE_T dwRegionSize


CreateMemoryResourceNotification
================================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** MEMORY_RESOURCE_NOTIFICATION_TYPE NotificationType


QueryMemoryResourceNotification
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE ResourceNotificationHandle
    ** PBOOL ResourceState


GetSystemFileCacheSize
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PSIZE_T lpMinimumFileCacheSize
    ** PSIZE_T lpMaximumFileCacheSize
    ** PDWORD lpFlags


SetSystemFileCacheSize
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** SIZE_T MinimumFileCacheSize
    ** SIZE_T MaximumFileCacheSize
    ** DWORD Flags


CreateFileMappingNumaW
======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** HANDLE hFile
    ** LPSECURITY_ATTRIBUTES lpFileMappingAttributes
    ** DWORD flProtect
    ** DWORD dwMaximumSizeHigh
    ** DWORD dwMaximumSizeLow
    ** LPCWSTR lpName
    ** DWORD nndPreferred


AllocateUserPhysicalPages
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PULONG_PTR NumberOfPages
    ** PULONG_PTR PageArray


FreeUserPhysicalPages
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PULONG_PTR NumberOfPages
    ** PULONG_PTR PageArray


MapUserPhysicalPages
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PVOID VirtualAddress
    ** ULONG_PTR NumberOfPages
    ** PULONG_PTR PageArray


AllocateUserPhysicalPagesNuma
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PULONG_PTR NumberOfPages
    ** PULONG_PTR PageArray
    ** DWORD nndPreferred


VirtualAllocExNuma
==================

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** HANDLE hProcess
    ** LPVOID lpAddress
    ** SIZE_T dwSize
    ** DWORD flAllocationType
    ** DWORD flProtect
    ** DWORD nndPreferred


GetMemoryErrorHandlingCapabilities
==================================

Signature::

    * Library: 
    * Return value: BOOL

Parameters::

    ** PULONG Capabilities


RegisterBadMemoryNotification
=============================

Signature::

    * Library: 
    * Return value: PVOID

Parameters::

    ** PBAD_MEMORY_CALLBACK_ROUTINE Callback


UnregisterBadMemoryNotification
===============================

Signature::

    * Library: 
    * Return value: BOOL

Parameters::

    ** PVOID RegistrationHandle


CreatePipe
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PHANDLE hReadPipe
    ** PHANDLE hWritePipe
    ** LPSECURITY_ATTRIBUTES lpPipeAttributes
    ** DWORD nSize


ConnectNamedPipe
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hNamedPipe
    ** LPOVERLAPPED lpOverlapped


DisconnectNamedPipe
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hNamedPipe


SetNamedPipeHandleState
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hNamedPipe
    ** LPDWORD lpMode
    ** LPDWORD lpMaxCollectionCount
    ** LPDWORD lpCollectDataTimeout


PeekNamedPipe
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hNamedPipe
    ** LPVOID lpBuffer
    ** DWORD nBufferSize
    ** LPDWORD lpBytesRead
    ** LPDWORD lpTotalBytesAvail
    ** LPDWORD lpBytesLeftThisMessage


TransactNamedPipe
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hNamedPipe
    ** LPVOID lpInBuffer
    ** DWORD nInBufferSize
    ** LPVOID lpOutBuffer
    ** DWORD nOutBufferSize
    ** LPDWORD lpBytesRead
    ** LPOVERLAPPED lpOverlapped


CreateNamedPipeW
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpName
    ** DWORD dwOpenMode
    ** DWORD dwPipeMode
    ** DWORD nMaxInstances
    ** DWORD nOutBufferSize
    ** DWORD nInBufferSize
    ** DWORD nDefaultTimeOut
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes


WaitNamedPipeW
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpNamedPipeName
    ** DWORD nTimeOut


GetNamedPipeClientComputerNameW
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE Pipe
    ** LPWSTR ClientComputerName
    ** ULONG ClientComputerNameLength


CreatePrivateNamespaceW
=======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpPrivateNamespaceAttributes
    ** LPVOID lpBoundaryDescriptor
    ** LPCWSTR lpAliasPrefix


OpenPrivateNamespaceW
=====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPVOID lpBoundaryDescriptor
    ** LPCWSTR lpAliasPrefix


ClosePrivateNamespace
=====================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    ** HANDLE Handle
    ** ULONG Flags


CreateBoundaryDescriptorW
=========================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR Name
    ** ULONG Flags


AddSIDToBoundaryDescriptor
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE *BoundaryDescriptor
    ** PSID RequiredSid


DeleteBoundaryDescriptor
========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** HANDLE BoundaryDescriptor


GetEnvironmentStrings
=====================

Signature::

    * Library: kernel32
    * Return value: LPCH


GetEnvironmentStringsW
======================

Signature::

    * Library: kernel32
    * Return value: LPWCH


SetEnvironmentStringsW
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPWCH NewEnvironment


FreeEnvironmentStringsA
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCH penv


FreeEnvironmentStringsW
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPWCH penv


GetStdHandle
============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD nStdHandle


SetStdHandle
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD nStdHandle
    ** HANDLE hHandle


SetStdHandleEx
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD nStdHandle
    ** HANDLE hHandle
    ** PHANDLE phPrevValue


GetCommandLineA
===============

Signature::

    * Library: kernel32
    * Return value: LPSTR


GetCommandLineW
===============

Signature::

    * Library: kernel32
    * Return value: LPWSTR


GetEnvironmentVariableA
=======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpName
    ** LPSTR lpBuffer
    ** DWORD nSize


GetEnvironmentVariableW
=======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpName
    ** LPWSTR lpBuffer
    ** DWORD nSize


SetEnvironmentVariableA
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpName
    ** LPCSTR lpValue


SetEnvironmentVariableW
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpName
    ** LPCWSTR lpValue


ExpandEnvironmentStringsA
=========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpSrc
    ** LPSTR lpDst
    ** DWORD nSize


ExpandEnvironmentStringsW
=========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpSrc
    ** LPWSTR lpDst
    ** DWORD nSize


SetCurrentDirectoryA
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpPathName


SetCurrentDirectoryW
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpPathName


GetCurrentDirectoryA
====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPSTR lpBuffer


GetCurrentDirectoryW
====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPWSTR lpBuffer


SearchPathW
===========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpPath
    ** LPCWSTR lpFileName
    ** LPCWSTR lpExtension
    ** DWORD nBufferLength
    ** LPWSTR lpBuffer
    ** LPWSTR *lpFilePart


SearchPathA
===========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpPath
    ** LPCSTR lpFileName
    ** LPCSTR lpExtension
    ** DWORD nBufferLength
    ** LPSTR lpBuffer
    ** LPSTR *lpFilePart


NeedCurrentDirectoryForExePathA
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR ExeName


NeedCurrentDirectoryForExePathW
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR ExeName


QueueUserAPC
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** PAPCFUNC pfnAPC
    ** HANDLE hThread
    ** ULONG_PTR dwData


GetProcessTimes
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** LPFILETIME lpCreationTime
    ** LPFILETIME lpExitTime
    ** LPFILETIME lpKernelTime
    ** LPFILETIME lpUserTime


GetCurrentProcess
=================

Signature::

    * Library: kernel32
    * Return value: HANDLE


GetCurrentProcessId
===================

Signature::

    * Library: kernel32
    * Return value: DWORD


ExitProcess
===========

Signature::

    * Library: kernel32
    * Return value: DECLSPEC_NORETURN

Parameters::

    ** UINT uExitCode


TerminateProcess
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** UINT uExitCode


GetExitCodeProcess
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** LPDWORD lpExitCode


SwitchToThread
==============

Signature::

    * Library: kernel32
    * Return value: BOOL


CreateThread
============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpThreadAttributes
    ** SIZE_T dwStackSize
    ** LPTHREAD_START_ROUTINE lpStartAddress
    ** LPVOID lpParameter
    ** DWORD dwCreationFlags
    ** LPDWORD lpThreadId


CreateRemoteThread
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** HANDLE hProcess
    ** LPSECURITY_ATTRIBUTES lpThreadAttributes
    ** SIZE_T dwStackSize
    ** LPTHREAD_START_ROUTINE lpStartAddress
    ** LPVOID lpParameter
    ** DWORD dwCreationFlags
    ** LPDWORD lpThreadId


GetCurrentThread
================

Signature::

    * Library: kernel32
    * Return value: HANDLE


GetCurrentThreadId
==================

Signature::

    * Library: kernel32
    * Return value: DWORD


OpenThread
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** DWORD dwThreadId


SetThreadPriority
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** int nPriority


SetThreadPriorityBoost
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** BOOL bDisablePriorityBoost


GetThreadPriorityBoost
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PBOOL pDisablePriorityBoost


GetThreadPriority
=================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** HANDLE hThread


ExitThread
==========

Signature::

    * Library: kernel32
    * Return value: DECLSPEC_NORETURN

Parameters::

    ** DWORD dwExitCode


TerminateThread
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** DWORD dwExitCode


GetExitCodeThread
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** LPDWORD lpExitCode


SuspendThread
=============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hThread


ResumeThread
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hThread


TlsAlloc
========

Signature::

    * Library: kernel32
    * Return value: DWORD


TlsGetValue
===========

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** DWORD dwTlsIndex


TlsSetValue
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwTlsIndex
    ** LPVOID lpTlsValue


TlsFree
=======

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwTlsIndex


CreateProcessA
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpApplicationName
    ** LPSTR lpCommandLine
    ** LPSECURITY_ATTRIBUTES lpProcessAttributes
    ** LPSECURITY_ATTRIBUTES lpThreadAttributes
    ** BOOL bInheritHandles
    ** DWORD dwCreationFlags
    ** LPVOID lpEnvironment
    ** LPCSTR lpCurrentDirectory
    ** LPSTARTUPINFOA lpStartupInfo
    ** LPPROCESS_INFORMATION lpProcessInformation


CreateProcessW
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpApplicationName
    ** LPWSTR lpCommandLine
    ** LPSECURITY_ATTRIBUTES lpProcessAttributes
    ** LPSECURITY_ATTRIBUTES lpThreadAttributes
    ** BOOL bInheritHandles
    ** DWORD dwCreationFlags
    ** LPVOID lpEnvironment
    ** LPCWSTR lpCurrentDirectory
    ** LPSTARTUPINFOW lpStartupInfo
    ** LPPROCESS_INFORMATION lpProcessInformation


SetProcessShutdownParameters
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwLevel
    ** DWORD dwFlags


GetProcessVersion
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD ProcessId


GetStartupInfoW
===============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSTARTUPINFOW lpStartupInfo


SetPriorityClass
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** DWORD dwPriorityClass


SetThreadStackGuarantee
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PULONG StackSizeInBytes


GetPriorityClass
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess


ProcessIdToSessionId
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwProcessId
    ** DWORD *pSessionId


GetProcessId
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE Process


GetThreadId
===========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE Thread


FlushProcessWriteBuffers
========================

Signature::

    * Library: kernel32
    * Return value: void


GetProcessIdOfThread
====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE Thread


InitializeProcThreadAttributeList
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
    ** DWORD dwAttributeCount
    ** DWORD dwFlags
    ** PSIZE_T lpSize


DeleteProcThreadAttributeList
=============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList


SetProcessAffinityUpdateMode
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** DWORD dwFlags


QueryProcessAffinityUpdateMode
==============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** LPDWORD lpdwFlags


UpdateProcThreadAttribute
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
    ** DWORD dwFlags
    ** DWORD_PTR Attribute
    ** PVOID lpValue
    ** SIZE_T cbSize
    ** PVOID lpPreviousValue
    ** PSIZE_T lpReturnSize


CreateRemoteThreadEx
====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** HANDLE hProcess
    ** LPSECURITY_ATTRIBUTES lpThreadAttributes
    ** SIZE_T dwStackSize
    ** LPTHREAD_START_ROUTINE lpStartAddress
    ** LPVOID lpParameter
    ** DWORD dwCreationFlags
    ** LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
    ** LPDWORD lpThreadId


GetCurrentThreadStackLimits
===========================

Signature::

    * Library: 
    * Return value: void

Parameters::

    ** PULONG_PTR LowLimit
    ** PULONG_PTR HighLimit


GetThreadContext
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** LPCONTEXT lpContext


SetThreadContext
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** CONTEXT *lpContext


SetProcessMitigationPolicy
==========================

Signature::

    * Library: 
    * Return value: BOOL

Parameters::

    ** PROCESS_MITIGATION_POLICY MitigationPolicy
    ** PVOID lpBuffer
    ** SIZE_T dwLength


GetProcessMitigationPolicy
==========================

Signature::

    * Library: 
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PROCESS_MITIGATION_POLICY MitigationPolicy
    ** PVOID lpBuffer
    ** SIZE_T dwLength


FlushInstructionCache
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** LPCVOID lpBaseAddress
    ** SIZE_T dwSize


GetThreadTimes
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** LPFILETIME lpCreationTime
    ** LPFILETIME lpExitTime
    ** LPFILETIME lpKernelTime
    ** LPFILETIME lpUserTime


OpenProcess
===========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** DWORD dwProcessId


GetProcessHandleCount
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PDWORD pdwHandleCount


GetCurrentProcessorNumber
=========================

Signature::

    * Library: kernel32
    * Return value: DWORD


SetThreadIdealProcessorEx
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PPROCESSOR_NUMBER lpIdealProcessor
    ** PPROCESSOR_NUMBER lpPreviousIdealProcessor


GetThreadIdealProcessorEx
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PPROCESSOR_NUMBER lpIdealProcessor


GetCurrentProcessorNumberEx
===========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PPROCESSOR_NUMBER ProcNumber


GetProcessPriorityBoost
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PBOOL pDisablePriorityBoost


SetProcessPriorityBoost
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** BOOL bDisablePriorityBoost


GetThreadIOPendingFlag
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PBOOL lpIOIsPending


GetSystemTimes
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PFILETIME lpIdleTime
    ** PFILETIME lpKernelTime
    ** PFILETIME lpUserTime


GetThreadInformation
====================

Signature::

    * Library: 
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** THREAD_INFORMATION_CLASS ThreadInformationClass
    ** LPVOID ThreadInformation
    ** DWORD ThreadInformationSize


SetThreadInformation
====================

Signature::

    * Library: 
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** THREAD_INFORMATION_CLASS ThreadInformationClass
    ** LPVOID ThreadInformation
    ** DWORD ThreadInformationSize


GetProcessGroupAffinity
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PUSHORT GroupCount
    ** PUSHORT GroupArray


GetThreadGroupAffinity
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PGROUP_AFFINITY GroupAffinity


SetThreadGroupAffinity
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** GROUP_AFFINITY *GroupAffinity
    ** PGROUP_AFFINITY PreviousGroupAffinity


QueryPerformanceCounter
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LARGE_INTEGER *lpPerformanceCount


QueryPerformanceFrequency
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LARGE_INTEGER *lpFrequency


QueryThreadCycleTime
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE ThreadHandle
    ** PULONG64 CycleTime


QueryProcessCycleTime
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE ProcessHandle
    ** PULONG64 CycleTime


QueryIdleProcessorCycleTime
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PULONG BufferLength
    ** PULONG64 ProcessorIdleCycleTime


QueryIdleProcessorCycleTimeEx
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** USHORT Group
    ** PULONG BufferLength
    ** PULONG64 ProcessorIdleCycleTime


QueryUnbiasedInterruptTime
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PULONGLONG UnbiasedTime


CompareStringEx
===============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCWSTR lpLocaleName
    ** DWORD dwCmpFlags
    ** LPCWCH lpString1
    ** int cchCount1
    ** LPCWCH lpString2
    ** int cchCount2
    ** LPNLSVERSIONINFO lpVersionInformation
    ** LPVOID lpReserved
    ** LPARAM lParam


CompareStringOrdinal
====================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCWCH lpString1
    ** int cchCount1
    ** LPCWCH lpString2
    ** int cchCount2
    ** BOOL bIgnoreCase


CompareStringW
==============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwCmpFlags
    ** PCNZWCH lpString1
    ** int cchCount1
    ** PCNZWCH lpString2
    ** int cchCount2


FoldStringW
===========

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** DWORD dwMapFlags
    ** LPCWCH lpSrcStr
    ** int cchSrc
    ** LPWSTR lpDestStr
    ** int cchDest


GetStringTypeExW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LCID Locale
    ** DWORD dwInfoType
    ** LPCWCH lpSrcStr
    ** int cchSrc
    ** LPWORD lpCharType


GetStringTypeW
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwInfoType
    ** LPCWCH lpSrcStr
    ** int cchSrc
    ** LPWORD lpCharType


MultiByteToWideChar
===================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** UINT CodePage
    ** DWORD dwFlags
    ** LPCCH lpMultiByteStr
    ** int cbMultiByte
    ** LPWSTR lpWideCharStr
    ** int cchWideChar


WideCharToMultiByte
===================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** UINT CodePage
    ** DWORD dwFlags
    ** LPCWCH lpWideCharStr
    ** int cchWideChar
    ** LPSTR lpMultiByteStr
    ** int cbMultiByte
    ** LPCCH lpDefaultChar
    ** LPBOOL lpUsedDefaultChar


InitializeSRWLock
=================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PSRWLOCK SRWLock


ReleaseSRWLockExclusive
=======================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PSRWLOCK SRWLock


ReleaseSRWLockShared
====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PSRWLOCK SRWLock


AcquireSRWLockExclusive
=======================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PSRWLOCK SRWLock


AcquireSRWLockShared
====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PSRWLOCK SRWLock


TryAcquireSRWLockExclusive
==========================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    ** PSRWLOCK SRWLock


TryAcquireSRWLockShared
=======================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    ** PSRWLOCK SRWLock


InitializeCriticalSection
=========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPCRITICAL_SECTION lpCriticalSection


EnterCriticalSection
====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPCRITICAL_SECTION lpCriticalSection


LeaveCriticalSection
====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPCRITICAL_SECTION lpCriticalSection


InitializeCriticalSectionAndSpinCount
=====================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCRITICAL_SECTION lpCriticalSection
    ** DWORD dwSpinCount


InitializeCriticalSectionEx
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCRITICAL_SECTION lpCriticalSection
    ** DWORD dwSpinCount
    ** DWORD Flags


SetCriticalSectionSpinCount
===========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCRITICAL_SECTION lpCriticalSection
    ** DWORD dwSpinCount


TryEnterCriticalSection
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCRITICAL_SECTION lpCriticalSection


DeleteCriticalSection
=====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPCRITICAL_SECTION lpCriticalSection


InitOnceInitialize
==================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PINIT_ONCE InitOnce


InitOnceExecuteOnce
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PINIT_ONCE InitOnce
    ** PINIT_ONCE_FN InitFn
    ** PVOID Parameter
    ** LPVOID *Context


InitOnceBeginInitialize
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPINIT_ONCE lpInitOnce
    ** DWORD dwFlags
    ** PBOOL fPending
    ** LPVOID *lpContext


InitOnceComplete
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPINIT_ONCE lpInitOnce
    ** DWORD dwFlags
    ** LPVOID lpContext


InitializeConditionVariable
===========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PCONDITION_VARIABLE ConditionVariable


WakeConditionVariable
=====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PCONDITION_VARIABLE ConditionVariable


WakeAllConditionVariable
========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PCONDITION_VARIABLE ConditionVariable


SleepConditionVariableCS
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PCONDITION_VARIABLE ConditionVariable
    ** PCRITICAL_SECTION CriticalSection
    ** DWORD dwMilliseconds


SleepConditionVariableSRW
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PCONDITION_VARIABLE ConditionVariable
    ** PSRWLOCK SRWLock
    ** DWORD dwMilliseconds
    ** ULONG Flags


SetEvent
========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hEvent


ResetEvent
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hEvent


ReleaseSemaphore
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSemaphore
    ** LONG lReleaseCount
    ** LPLONG lpPreviousCount


ReleaseMutex
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hMutex


WaitForSingleObject
===================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hHandle
    ** DWORD dwMilliseconds


SleepEx
=======

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD dwMilliseconds
    ** BOOL bAlertable


WaitForSingleObjectEx
=====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hHandle
    ** DWORD dwMilliseconds
    ** BOOL bAlertable


WaitForMultipleObjectsEx
========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nCount
    ** HANDLE *lpHandles
    ** BOOL bWaitAll
    ** DWORD dwMilliseconds
    ** BOOL bAlertable


CreateMutexA
============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpMutexAttributes
    ** BOOL bInitialOwner
    ** LPCSTR lpName


CreateMutexW
============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpMutexAttributes
    ** BOOL bInitialOwner
    ** LPCWSTR lpName


OpenMutexW
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCWSTR lpName


CreateEventA
============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpEventAttributes
    ** BOOL bManualReset
    ** BOOL bInitialState
    ** LPCSTR lpName


CreateEventW
============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpEventAttributes
    ** BOOL bManualReset
    ** BOOL bInitialState
    ** LPCWSTR lpName


OpenEventA
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCSTR lpName


OpenEventW
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCWSTR lpName


OpenSemaphoreW
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCWSTR lpName


OpenWaitableTimerW
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCWSTR lpTimerName


SetWaitableTimer
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hTimer
    ** const LARGE_INTEGER *lpDueTime
    ** LONG lPeriod
    ** PTIMERAPCROUTINE pfnCompletionRoutine
    ** LPVOID lpArgToCompletionRoutine
    ** BOOL fResume


CancelWaitableTimer
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hTimer


CreateMutexExA
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpMutexAttributes
    ** LPCSTR lpName
    ** DWORD dwFlags
    ** DWORD dwDesiredAccess


CreateMutexExW
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpMutexAttributes
    ** LPCWSTR lpName
    ** DWORD dwFlags
    ** DWORD dwDesiredAccess


CreateEventExA
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpEventAttributes
    ** LPCSTR lpName
    ** DWORD dwFlags
    ** DWORD dwDesiredAccess


CreateEventExW
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpEventAttributes
    ** LPCWSTR lpName
    ** DWORD dwFlags
    ** DWORD dwDesiredAccess


CreateSemaphoreExW
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpSemaphoreAttributes
    ** LONG lInitialCount
    ** LONG lMaximumCount
    ** LPCWSTR lpName
    ** DWORD dwFlags
    ** DWORD dwDesiredAccess


CreateWaitableTimerExW
======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpTimerAttributes
    ** LPCWSTR lpTimerName
    ** DWORD dwFlags
    ** DWORD dwDesiredAccess


Sleep
=====

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** DWORD dwMilliseconds


SignalObjectAndWait
===================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hObjectToSignal
    ** HANDLE hObjectToWaitOn
    ** DWORD dwMilliseconds
    ** BOOL bAlertable


GetVersion
==========

Signature::

    * Library: kernel32
    * Return value: DWORD


GlobalMemoryStatusEx
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPMEMORYSTATUSEX lpBuffer


GetSystemTime
=============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSYSTEMTIME lpSystemTime


GetSystemTimeAsFileTime
=======================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPFILETIME lpSystemTimeAsFileTime


GetLocalTime
============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSYSTEMTIME lpSystemTime


SetLocalTime
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** SYSTEMTIME *lpSystemTime


GetSystemInfo
=============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSYSTEM_INFO lpSystemInfo


GetTickCount
============

Signature::

    * Library: kernel32
    * Return value: DWORD


GetTickCount64
==============

Signature::

    * Library: kernel32
    * Return value: ULONGLONG


GetSystemTimeAdjustment
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PDWORD lpTimeAdjustment
    ** PDWORD lpTimeIncrement
    ** PBOOL lpTimeAdjustmentDisabled


GetSystemDirectoryA
===================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPSTR lpBuffer
    ** UINT uSize


GetSystemDirectoryW
===================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPWSTR lpBuffer
    ** UINT uSize


GetWindowsDirectoryA
====================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPSTR lpBuffer
    ** UINT uSize


GetWindowsDirectoryW
====================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPWSTR lpBuffer
    ** UINT uSize


GetSystemWindowsDirectoryA
==========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPSTR lpBuffer
    ** UINT uSize


GetSystemWindowsDirectoryW
==========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPWSTR lpBuffer
    ** UINT uSize


GetComputerNameExA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** COMPUTER_NAME_FORMAT NameType
    ** LPSTR lpBuffer
    ** LPDWORD nSize


GetComputerNameExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** COMPUTER_NAME_FORMAT NameType
    ** LPWSTR lpBuffer
    ** LPDWORD nSize


SetComputerNameExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** COMPUTER_NAME_FORMAT NameType
    ** LPCWSTR lpBuffer


SetSystemTime
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** SYSTEMTIME *lpSystemTime


GetVersionExA
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPOSVERSIONINFOA lpVersionInformation


GetVersionExW
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPOSVERSIONINFOW lpVersionInformation


GetLogicalProcessorInformation
==============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PSYSTEM_LOGICAL_PROCESSOR_INFORMATION Buffer
    ** PDWORD ReturnedLength


GetLogicalProcessorInformationEx
================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType
    ** PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Buffer
    ** PDWORD ReturnedLength


GetNativeSystemInfo
===================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSYSTEM_INFO lpSystemInfo


GetProductInfo
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwOSMajorVersion
    ** DWORD dwOSMinorVersion
    ** DWORD dwSpMajorVersion
    ** DWORD dwSpMinorVersion
    ** PDWORD pdwReturnedProductType


EnumSystemFirmwareTables
========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** DWORD FirmwareTableProviderSignature
    ** PVOID pFirmwareTableEnumBuffer
    ** DWORD BufferSize


GetSystemFirmwareTable
======================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** DWORD FirmwareTableProviderSignature
    ** DWORD FirmwareTableID
    ** PVOID pFirmwareTableBuffer
    ** DWORD BufferSize


GetPhysicallyInstalledSystemMemory
==================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PULONGLONG TotalMemoryInKilobytes


SetSystemTimeAdjustment
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwTimeAdjustment
    ** BOOL bTimeAdjustmentDisabled


GetNumaHighestNodeNumber
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PULONG HighestNodeNumber


GetNumaNodeProcessorMaskEx
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** USHORT Node
    ** PGROUP_AFFINITY ProcessorMask


CreateThreadpool
================

Signature::

    * Library: kernel32
    * Return value: PTP_POOL

Parameters::

    ** PVOID reserved


SetThreadpoolThreadMaximum
==========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_POOL ptpp
    ** DWORD cthrdMost


SetThreadpoolThreadMinimum
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_POOL ptpp
    ** DWORD cthrdMic


SetThreadpoolStackInformation
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_POOL ptpp
    ** PTP_POOL_STACK_INFORMATION ptpsi


QueryThreadpoolStackInformation
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_POOL ptpp
    ** PTP_POOL_STACK_INFORMATION ptpsi


CloseThreadpool
===============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_POOL ptpp


CreateThreadpoolCleanupGroup
============================

Signature::

    * Library: kernel32
    * Return value: PTP_CLEANUP_GROUP


CloseThreadpoolCleanupGroupMembers
==================================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CLEANUP_GROUP ptpcg
    ** BOOL fCancelPendingCallbacks
    ** PVOID pvCleanupContext


CloseThreadpoolCleanupGroup
===========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CLEANUP_GROUP ptpcg


SetEventWhenCallbackReturns
===========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** HANDLE evt


ReleaseSemaphoreWhenCallbackReturns
===================================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** HANDLE sem
    ** DWORD crel


ReleaseMutexWhenCallbackReturns
===============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** HANDLE mut


LeaveCriticalSectionWhenCallbackReturns
=======================================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** PCRITICAL_SECTION pcs


FreeLibraryWhenCallbackReturns
==============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** HMODULE mod


CallbackMayRunLong
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_CALLBACK_INSTANCE pci


DisassociateCurrentThreadFromCallback
=====================================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci


TrySubmitThreadpoolCallback
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_SIMPLE_CALLBACK pfns
    ** PVOID pv
    ** PTP_CALLBACK_ENVIRON pcbe


CreateThreadpoolWork
====================

Signature::

    * Library: kernel32
    * Return value: PTP_WORK

Parameters::

    ** PTP_WORK_CALLBACK pfnwk
    ** PVOID pv
    ** PTP_CALLBACK_ENVIRON pcbe


SubmitThreadpoolWork
====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WORK pwk


WaitForThreadpoolWorkCallbacks
==============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WORK pwk
    ** BOOL fCancelPendingCallbacks


CloseThreadpoolWork
===================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WORK pwk


CreateThreadpoolTimer
=====================

Signature::

    * Library: kernel32
    * Return value: PTP_TIMER

Parameters::

    ** PTP_TIMER_CALLBACK pfnti
    ** PVOID pv
    ** PTP_CALLBACK_ENVIRON pcbe


SetThreadpoolTimer
==================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_TIMER pti
    ** PFILETIME pftDueTime
    ** DWORD msPeriod
    ** DWORD msWindowLength


IsThreadpoolTimerSet
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_TIMER pti


WaitForThreadpoolTimerCallbacks
===============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_TIMER pti
    ** BOOL fCancelPendingCallbacks


CloseThreadpoolTimer
====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_TIMER pti


CreateThreadpoolWait
====================

Signature::

    * Library: kernel32
    * Return value: PTP_WAIT

Parameters::

    ** PTP_WAIT_CALLBACK pfnwa
    ** PVOID pv
    ** PTP_CALLBACK_ENVIRON pcbe


SetThreadpoolWait
=================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WAIT pwa
    ** HANDLE h
    ** PFILETIME pftTimeout


WaitForThreadpoolWaitCallbacks
==============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WAIT pwa
    ** BOOL fCancelPendingCallbacks


CloseThreadpoolWait
===================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WAIT pwa


CreateThreadpoolIo
==================

Signature::

    * Library: kernel32
    * Return value: PTP_IO

Parameters::

    ** HANDLE fl
    ** PTP_WIN32_IO_CALLBACK pfnio
    ** PVOID pv
    ** PTP_CALLBACK_ENVIRON pcbe


StartThreadpoolIo
=================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_IO pio


CancelThreadpoolIo
==================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_IO pio


WaitForThreadpoolIoCallbacks
============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_IO pio
    ** BOOL fCancelPendingCallbacks


CloseThreadpoolIo
=================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_IO pio


QueueUserWorkItem
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPTHREAD_START_ROUTINE Function
    ** PVOID Context
    ** ULONG Flags


UnregisterWaitEx
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE WaitHandle
    ** HANDLE CompletionEvent


CreateTimerQueue
================

Signature::

    * Library: kernel32
    * Return value: HANDLE


CreateTimerQueueTimer
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PHANDLE phNewTimer
    ** HANDLE TimerQueue
    ** WAITORTIMERCALLBACK Callback
    ** PVOID Parameter
    ** DWORD DueTime
    ** DWORD Period
    ** ULONG Flags


ChangeTimerQueueTimer
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE TimerQueue
    ** HANDLE Timer
    ** ULONG DueTime
    ** ULONG Period


DeleteTimerQueueTimer
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE TimerQueue
    ** HANDLE Timer
    ** HANDLE CompletionEvent


DeleteTimerQueueEx
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE TimerQueue
    ** HANDLE CompletionEvent


SystemTimeToTzSpecificLocalTime
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** TIME_ZONE_INFORMATION *lpTimeZoneInformation
    ** SYSTEMTIME *lpUniversalTime
    ** LPSYSTEMTIME lpLocalTime


TzSpecificLocalTimeToSystemTime
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** TIME_ZONE_INFORMATION *lpTimeZoneInformation
    ** SYSTEMTIME *lpLocalTime
    ** LPSYSTEMTIME lpUniversalTime


FileTimeToSystemTime
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** FILETIME *lpFileTime
    ** LPSYSTEMTIME lpSystemTime


SystemTimeToFileTime
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** SYSTEMTIME *lpSystemTime
    ** LPFILETIME lpFileTime


GetTimeZoneInformation
======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPTIME_ZONE_INFORMATION lpTimeZoneInformation


SetTimeZoneInformation
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** TIME_ZONE_INFORMATION *lpTimeZoneInformation


SetDynamicTimeZoneInformation
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DYNAMIC_TIME_ZONE_INFORMATION *lpTimeZoneInformation


GetDynamicTimeZoneInformation
=============================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** PDYNAMIC_TIME_ZONE_INFORMATION pTimeZoneInformation


SystemTimeToTzSpecificLocalTimeEx
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DYNAMIC_TIME_ZONE_INFORMATION *lpTimeZoneInformation
    ** SYSTEMTIME *lpUniversalTime
    ** LPSYSTEMTIME lpLocalTime


TzSpecificLocalTimeToSystemTimeEx
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DYNAMIC_TIME_ZONE_INFORMATION *lpTimeZoneInformation
    ** SYSTEMTIME *lpLocalTime
    ** LPSYSTEMTIME lpUniversalTime


EncodePointer
=============

Signature::

    * Library: kernel32
    * Return value: PVOID

Parameters::

    ** PVOID Ptr


DecodePointer
=============

Signature::

    * Library: kernel32
    * Return value: PVOID

Parameters::

    ** PVOID Ptr


EncodeSystemPointer
===================

Signature::

    * Library: kernel32
    * Return value: PVOID

Parameters::

    ** PVOID Ptr


DecodeSystemPointer
===================

Signature::

    * Library: kernel32
    * Return value: PVOID

Parameters::

    ** PVOID Ptr


Beep
====

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFreq
    ** DWORD dwDuration


GlobalAlloc
===========

Signature::

    * Library: kernel32
    * Return value: HGLOBAL

Parameters::

    ** UINT uFlags
    ** SIZE_T dwBytes


GlobalReAlloc
=============

Signature::

    * Library: kernel32
    * Return value: HGLOBAL

Parameters::

    ** HGLOBAL hMem
    ** SIZE_T dwBytes
    ** UINT uFlags


GlobalSize
==========

Signature::

    * Library: kernel32
    * Return value: SIZE_T

Parameters::

    ** HGLOBAL hMem


GlobalFlags
===========

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** HGLOBAL hMem


GlobalLock
==========

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** HGLOBAL hMem


GlobalHandle
============

Signature::

    * Library: kernel32
    * Return value: HGLOBAL

Parameters::

    ** LPCVOID pMem


GlobalUnlock
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HGLOBAL hMem


GlobalFree
==========

Signature::

    * Library: kernel32
    * Return value: HGLOBAL

Parameters::

    ** HGLOBAL hMem


GlobalCompact
=============

Signature::

    * Library: kernel32
    * Return value: SIZE_T

Parameters::

    ** DWORD dwMinFree


GlobalFix
=========

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** HGLOBAL hMem


GlobalUnfix
===========

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** HGLOBAL hMem


GlobalWire
==========

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** HGLOBAL hMem


GlobalUnWire
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HGLOBAL hMem


GlobalMemoryStatus
==================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPMEMORYSTATUS lpBuffer


LocalAlloc
==========

Signature::

    * Library: kernel32
    * Return value: HLOCAL

Parameters::

    ** UINT uFlags
    ** SIZE_T uBytes


LocalReAlloc
============

Signature::

    * Library: kernel32
    * Return value: HLOCAL

Parameters::

    ** HLOCAL hMem
    ** SIZE_T uBytes
    ** UINT uFlags


LocalLock
=========

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** HLOCAL hMem


LocalHandle
===========

Signature::

    * Library: kernel32
    * Return value: HLOCAL

Parameters::

    ** LPCVOID pMem


LocalUnlock
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HLOCAL hMem


LocalSize
=========

Signature::

    * Library: kernel32
    * Return value: SIZE_T

Parameters::

    ** HLOCAL hMem


LocalFlags
==========

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** HLOCAL hMem


LocalFree
=========

Signature::

    * Library: kernel32
    * Return value: HLOCAL

Parameters::

    ** HLOCAL hMem


LocalShrink
===========

Signature::

    * Library: kernel32
    * Return value: SIZE_T

Parameters::

    ** HLOCAL hMem
    ** UINT cbNewSize


LocalCompact
============

Signature::

    * Library: kernel32
    * Return value: SIZE_T

Parameters::

    ** UINT uMinFree


GetProcessorSystemCycleTime
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** USHORT Group
    ** PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION Buffer
    ** PDWORD ReturnedLength


GetBinaryTypeA
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpApplicationName
    ** LPDWORD lpBinaryType


GetBinaryTypeW
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpApplicationName
    ** LPDWORD lpBinaryType


GetShortPathNameA
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpszLongPath
    ** LPSTR lpszShortPath
    ** DWORD cchBuffer


GetLongPathNameTransactedA
==========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpszShortPath
    ** LPSTR lpszLongPath
    ** DWORD cchBuffer
    ** HANDLE hTransaction


GetLongPathNameTransactedW
==========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpszShortPath
    ** LPWSTR lpszLongPath
    ** DWORD cchBuffer
    ** HANDLE hTransaction


GetProcessAffinityMask
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PDWORD_PTR lpProcessAffinityMask
    ** PDWORD_PTR lpSystemAffinityMask


SetProcessAffinityMask
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** DWORD_PTR dwProcessAffinityMask


GetProcessIoCounters
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PIO_COUNTERS lpIoCounters


GetProcessWorkingSetSize
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PSIZE_T lpMinimumWorkingSetSize
    ** PSIZE_T lpMaximumWorkingSetSize


SetProcessWorkingSetSize
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** SIZE_T dwMinimumWorkingSetSize
    ** SIZE_T dwMaximumWorkingSetSize


FatalExit
=========

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** int ExitCode


SetEnvironmentStringsA
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCH NewEnvironment


RaiseFailFastException
======================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PEXCEPTION_RECORD pExceptionRecord
    ** PCONTEXT pContextRecord
    ** DWORD dwFlags


SwitchToFiber
=============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPVOID lpFiber


DeleteFiber
===========

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPVOID lpFiber


ConvertFiberToThread
====================

Signature::

    * Library: kernel32
    * Return value: BOOL


CreateFiberEx
=============

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** SIZE_T dwStackCommitSize
    ** SIZE_T dwStackReserveSize
    ** DWORD dwFlags
    ** LPFIBER_START_ROUTINE lpStartAddress
    ** LPVOID lpParameter


ConvertThreadToFiberEx
======================

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** LPVOID lpParameter
    ** DWORD dwFlags


CreateFiber
===========

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** SIZE_T dwStackSize
    ** LPFIBER_START_ROUTINE lpStartAddress
    ** LPVOID lpParameter


ConvertThreadToFiber
====================

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** LPVOID lpParameter


SetThreadAffinityMask
=====================

Signature::

    * Library: kernel32
    * Return value: DWORD_PTR

Parameters::

    ** HANDLE hThread
    ** DWORD_PTR dwThreadAffinityMask


SetThreadIdealProcessor
=======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hThread
    ** DWORD dwIdealProcessor


SetProcessDEPPolicy
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags


GetProcessDEPPolicy
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** LPDWORD lpFlags
    ** PBOOL lpPermanent


RequestWakeupLatency
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LATENCY_TIME latency


IsSystemResumeAutomatic
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL


GetThreadSelectorEntry
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** DWORD dwSelector
    ** LPLDT_ENTRY lpSelectorEntry


SetThreadExecutionState
=======================

Signature::

    * Library: kernel32
    * Return value: EXECUTION_STATE

Parameters::

    ** EXECUTION_STATE esFlags


PowerCreateRequest
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** PREASON_CONTEXT Context


PowerSetRequest
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE PowerRequest
    ** POWER_REQUEST_TYPE RequestType


PowerClearRequest
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE PowerRequest
    ** POWER_REQUEST_TYPE RequestType


SetFileCompletionNotificationModes
==================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE FileHandle
    ** UCHAR Flags


GetThreadErrorMode
==================

Signature::

    * Library: kernel32
    * Return value: DWORD


SetThreadErrorMode
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwNewMode
    ** LPDWORD lpOldMode


Wow64GetThreadContext
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PWOW64_CONTEXT lpContext


Wow64SetThreadContext
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** WOW64_CONTEXT *lpContext


Wow64GetThreadSelectorEntry
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** DWORD dwSelector
    ** PWOW64_LDT_ENTRY lpSelectorEntry


Wow64SuspendThread
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hThread


DebugSetProcessKillOnExit
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** BOOL KillOnExit


DebugBreakProcess
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE Process


PulseEvent
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hEvent


WaitForMultipleObjects
======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nCount
    ** HANDLE *lpHandles
    ** BOOL bWaitAll
    ** DWORD dwMilliseconds


GlobalDeleteAtom
================

Signature::

    * Library: kernel32
    * Return value: ATOM

Parameters::

    ** ATOM nAtom


InitAtomTable
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD nSize


DeleteAtom
==========

Signature::

    * Library: kernel32
    * Return value: ATOM

Parameters::

    ** ATOM nAtom


SetHandleCount
==============

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** UINT uNumber


RequestDeviceWakeup
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hDevice


CancelDeviceWakeupRequest
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hDevice


GetDevicePowerState
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hDevice
    ** BOOL *pfOn


SetMessageWaitingIndicator
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hMsgIndicator
    ** ULONG ulMsgCount


SetFileShortNameA
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPCSTR lpShortName


SetFileShortNameW
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPCWSTR lpShortName


LoadModule
==========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpModuleName
    ** LPVOID lpParameterBlock


WinExec
=======

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPCSTR lpCmdLine
    ** UINT uCmdShow


SetTapePosition
===============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hDevice
    ** DWORD dwPositionMethod
    ** DWORD dwPartition
    ** DWORD dwOffsetLow
    ** DWORD dwOffsetHigh
    ** BOOL bImmediate


GetTapePosition
===============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hDevice
    ** DWORD dwPositionType
    ** LPDWORD lpdwPartition
    ** LPDWORD lpdwOffsetLow
    ** LPDWORD lpdwOffsetHigh


PrepareTape
===========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hDevice
    ** DWORD dwOperation
    ** BOOL bImmediate


EraseTape
=========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hDevice
    ** DWORD dwEraseType
    ** BOOL bImmediate


CreateTapePartition
===================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hDevice
    ** DWORD dwPartitionMethod
    ** DWORD dwCount
    ** DWORD dwSize


WriteTapemark
=============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hDevice
    ** DWORD dwTapemarkType
    ** DWORD dwTapemarkCount
    ** BOOL bImmediate


GetTapeStatus
=============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hDevice


GetTapeParameters
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hDevice
    ** DWORD dwOperation
    ** LPDWORD lpdwSize
    ** LPVOID lpTapeInformation


SetTapeParameters
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hDevice
    ** DWORD dwOperation
    ** LPVOID lpTapeInformation


MulDiv
======

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** int nNumber
    ** int nNumerator
    ** int nDenominator


GetSystemDEPPolicy
==================

Signature::

    * Library: kernel32
    * Return value: DEP_SYSTEM_POLICY_TYPE


GetSystemRegistryQuota
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PDWORD pdwQuotaAllowed
    ** PDWORD pdwQuotaUsed


FileTimeToDosDateTime
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** FILETIME *lpFileTime
    ** LPWORD lpFatDate
    ** LPWORD lpFatTime


DosDateTimeToFileTime
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** WORD wFatDate
    ** WORD wFatTime
    ** LPFILETIME lpFileTime


FormatMessageA
==============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD dwFlags
    ** LPCVOID lpSource
    ** DWORD dwMessageId
    ** DWORD dwLanguageId
    ** LPSTR lpBuffer
    ** DWORD nSize
    ** va_list *Arguments


FormatMessageW
==============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD dwFlags
    ** LPCVOID lpSource
    ** DWORD dwMessageId
    ** DWORD dwLanguageId
    ** LPWSTR lpBuffer
    ** DWORD nSize
    ** va_list *Arguments


GetNamedPipeInfo
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hNamedPipe
    ** LPDWORD lpFlags
    ** LPDWORD lpOutBufferSize
    ** LPDWORD lpInBufferSize
    ** LPDWORD lpMaxInstances


CreateMailslotA
===============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCSTR lpName
    ** DWORD nMaxMessageSize
    ** DWORD lReadTimeout
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateMailslotW
===============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpName
    ** DWORD nMaxMessageSize
    ** DWORD lReadTimeout
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes


GetMailslotInfo
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hMailslot
    ** LPDWORD lpMaxMessageSize
    ** LPDWORD lpNextSize
    ** LPDWORD lpMessageCount
    ** LPDWORD lpReadTimeout


SetMailslotInfo
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hMailslot
    ** DWORD lReadTimeout


lstrcmpA
========

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCSTR lpString1
    ** LPCSTR lpString2


lstrcmpW
========

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCWSTR lpString1
    ** LPCWSTR lpString2


lstrcmpiA
=========

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCSTR lpString1
    ** LPCSTR lpString2


lstrcmpiW
=========

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCWSTR lpString1
    ** LPCWSTR lpString2


lstrcpynA
=========

Signature::

    * Library: kernel32
    * Return value: LPSTR

Parameters::

    ** LPSTR lpString1
    ** LPCSTR lpString2
    ** int iMaxLength


lstrcpynW
=========

Signature::

    * Library: kernel32
    * Return value: LPWSTR

Parameters::

    ** LPWSTR lpString1
    ** LPCWSTR lpString2
    ** int iMaxLength


lstrcpyA
========

Signature::

    * Library: kernel32
    * Return value: LPSTR

Parameters::

    ** LPSTR lpString1
    ** LPCSTR lpString2


lstrcpyW
========

Signature::

    * Library: kernel32
    * Return value: LPWSTR

Parameters::

    ** LPWSTR lpString1
    ** LPCWSTR lpString2


lstrcatA
========

Signature::

    * Library: kernel32
    * Return value: LPSTR

Parameters::

    ** LPSTR lpString1
    ** LPCSTR lpString2


lstrcatW
========

Signature::

    * Library: kernel32
    * Return value: LPWSTR

Parameters::

    ** LPWSTR lpString1
    ** LPCWSTR lpString2


lstrlenA
========

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCSTR lpString


lstrlenW
========

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCWSTR lpString


OpenFile
========

Signature::

    * Library: kernel32
    * Return value: HFILE

Parameters::

    ** LPCSTR lpFileName
    ** LPOFSTRUCT lpReOpenBuff
    ** UINT uStyle


_lopen
======

Signature::

    * Library: kernel32
    * Return value: HFILE

Parameters::

    ** LPCSTR lpPathName
    ** int iReadWrite


_lcreat
=======

Signature::

    * Library: kernel32
    * Return value: HFILE

Parameters::

    ** LPCSTR lpPathName
    ** int iAttribute


_lread
======

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** HFILE hFile
    ** LPVOID lpBuffer
    ** UINT uBytes


_lwrite
=======

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** HFILE hFile
    ** LPCCH lpBuffer
    ** UINT uBytes


_hread
======

Signature::

    * Library: kernel32
    * Return value: long

Parameters::

    ** HFILE hFile
    ** LPVOID lpBuffer
    ** long lBytes


_hwrite
=======

Signature::

    * Library: kernel32
    * Return value: long

Parameters::

    ** HFILE hFile
    ** LPCCH lpBuffer
    ** long lBytes


_lclose
=======

Signature::

    * Library: kernel32
    * Return value: HFILE

Parameters::

    ** HFILE hFile


_llseek
=======

Signature::

    * Library: kernel32
    * Return value: LONG

Parameters::

    ** HFILE hFile
    ** LONG lOffset
    ** int iOrigin


BackupRead
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPBYTE lpBuffer
    ** DWORD nNumberOfBytesToRead
    ** LPDWORD lpNumberOfBytesRead
    ** BOOL bAbort
    ** BOOL bProcessSecurity
    ** LPVOID *lpContext


BackupSeek
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** DWORD dwLowBytesToSeek
    ** DWORD dwHighBytesToSeek
    ** LPDWORD lpdwLowByteSeeked
    ** LPDWORD lpdwHighByteSeeked
    ** LPVOID *lpContext


BackupWrite
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPBYTE lpBuffer
    ** DWORD nNumberOfBytesToWrite
    ** LPDWORD lpNumberOfBytesWritten
    ** BOOL bAbort
    ** BOOL bProcessSecurity
    ** LPVOID *lpContext


OpenMutexA
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCSTR lpName


CreateSemaphoreA
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpSemaphoreAttributes
    ** LONG lInitialCount
    ** LONG lMaximumCount
    ** LPCSTR lpName


CreateSemaphoreW
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpSemaphoreAttributes
    ** LONG lInitialCount
    ** LONG lMaximumCount
    ** LPCWSTR lpName


OpenSemaphoreA
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCSTR lpName


CreateWaitableTimerA
====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpTimerAttributes
    ** BOOL bManualReset
    ** LPCSTR lpTimerName


CreateWaitableTimerW
====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpTimerAttributes
    ** BOOL bManualReset
    ** LPCWSTR lpTimerName


OpenWaitableTimerA
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCSTR lpTimerName


CreateSemaphoreExA
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpSemaphoreAttributes
    ** LONG lInitialCount
    ** LONG lMaximumCount
    ** LPCSTR lpName
    ** DWORD dwFlags
    ** DWORD dwDesiredAccess


CreateWaitableTimerExA
======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpTimerAttributes
    ** LPCSTR lpTimerName
    ** DWORD dwFlags
    ** DWORD dwDesiredAccess


CreateFileMappingA
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** HANDLE hFile
    ** LPSECURITY_ATTRIBUTES lpFileMappingAttributes
    ** DWORD flProtect
    ** DWORD dwMaximumSizeHigh
    ** DWORD dwMaximumSizeLow
    ** LPCSTR lpName


CreateFileMappingNumaA
======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** HANDLE hFile
    ** LPSECURITY_ATTRIBUTES lpFileMappingAttributes
    ** DWORD flProtect
    ** DWORD dwMaximumSizeHigh
    ** DWORD dwMaximumSizeLow
    ** LPCSTR lpName
    ** DWORD nndPreferred


OpenFileMappingA
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCSTR lpName


GetLogicalDriveStringsA
=======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPSTR lpBuffer


LoadLibraryA
============

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    ** LPCSTR lpLibFileName


LoadLibraryW
============

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    ** LPCWSTR lpLibFileName


QueryFullProcessImageNameA
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** DWORD dwFlags
    ** LPSTR lpExeName
    ** PDWORD lpdwSize


QueryFullProcessImageNameW
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** DWORD dwFlags
    ** LPWSTR lpExeName
    ** PDWORD lpdwSize


GetProcessShutdownParameters
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPDWORD lpdwLevel
    ** LPDWORD lpdwFlags


FatalAppExitA
=============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** UINT uAction
    ** LPCSTR lpMessageText


FatalAppExitW
=============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** UINT uAction
    ** LPCWSTR lpMessageText


GetStartupInfoA
===============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSTARTUPINFOA lpStartupInfo


GetFirmwareEnvironmentVariableA
===============================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpName
    ** LPCSTR lpGuid
    ** PVOID pBuffer
    ** DWORD nSize


GetFirmwareEnvironmentVariableW
===============================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpName
    ** LPCWSTR lpGuid
    ** PVOID pBuffer
    ** DWORD nSize


SetFirmwareEnvironmentVariableA
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpName
    ** LPCSTR lpGuid
    ** PVOID pValue
    ** DWORD nSize


SetFirmwareEnvironmentVariableW
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpName
    ** LPCWSTR lpGuid
    ** PVOID pValue
    ** DWORD nSize


FindResourceA
=============

Signature::

    * Library: kernel32
    * Return value: HRSRC

Parameters::

    ** HMODULE hModule
    ** LPCSTR lpName
    ** LPCSTR lpType


FindResourceW
=============

Signature::

    * Library: kernel32
    * Return value: HRSRC

Parameters::

    ** HMODULE hModule
    ** LPCWSTR lpName
    ** LPCWSTR lpType


FindResourceExA
===============

Signature::

    * Library: kernel32
    * Return value: HRSRC

Parameters::

    ** HMODULE hModule
    ** LPCSTR lpType
    ** LPCSTR lpName
    ** WORD wLanguage


EnumResourceTypesA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hModule
    ** ENUMRESTYPEPROCA lpEnumFunc
    ** LONG_PTR lParam


EnumResourceTypesW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hModule
    ** ENUMRESTYPEPROCW lpEnumFunc
    ** LONG_PTR lParam


EnumResourceNamesA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hModule
    ** LPCSTR lpType
    ** ENUMRESNAMEPROCA lpEnumFunc
    ** LONG_PTR lParam


EnumResourceNamesW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hModule
    ** LPCWSTR lpType
    ** ENUMRESNAMEPROCW lpEnumFunc
    ** LONG_PTR lParam


EnumResourceLanguagesA
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hModule
    ** LPCSTR lpType
    ** LPCSTR lpName
    ** ENUMRESLANGPROCA lpEnumFunc
    ** LONG_PTR lParam


EnumResourceLanguagesW
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hModule
    ** LPCWSTR lpType
    ** LPCWSTR lpName
    ** ENUMRESLANGPROCW lpEnumFunc
    ** LONG_PTR lParam


BeginUpdateResourceA
====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCSTR pFileName
    ** BOOL bDeleteExistingResources


BeginUpdateResourceW
====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR pFileName
    ** BOOL bDeleteExistingResources


UpdateResourceA
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hUpdate
    ** LPCSTR lpType
    ** LPCSTR lpName
    ** WORD wLanguage
    ** LPVOID lpData
    ** DWORD cb


UpdateResourceW
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hUpdate
    ** LPCWSTR lpType
    ** LPCWSTR lpName
    ** WORD wLanguage
    ** LPVOID lpData
    ** DWORD cb


EndUpdateResourceA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hUpdate
    ** BOOL fDiscard


EndUpdateResourceW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hUpdate
    ** BOOL fDiscard


GlobalAddAtomA
==============

Signature::

    * Library: kernel32
    * Return value: ATOM

Parameters::

    ** LPCSTR lpString


GlobalAddAtomW
==============

Signature::

    * Library: kernel32
    * Return value: ATOM

Parameters::

    ** LPCWSTR lpString


GlobalFindAtomA
===============

Signature::

    * Library: kernel32
    * Return value: ATOM

Parameters::

    ** LPCSTR lpString


GlobalFindAtomW
===============

Signature::

    * Library: kernel32
    * Return value: ATOM

Parameters::

    ** LPCWSTR lpString


GlobalGetAtomNameA
==================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** ATOM nAtom
    ** LPSTR lpBuffer
    ** int nSize


GlobalGetAtomNameW
==================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** ATOM nAtom
    ** LPWSTR lpBuffer
    ** int nSize


AddAtomA
========

Signature::

    * Library: kernel32
    * Return value: ATOM

Parameters::

    ** LPCSTR lpString


AddAtomW
========

Signature::

    * Library: kernel32
    * Return value: ATOM

Parameters::

    ** LPCWSTR lpString


FindAtomA
=========

Signature::

    * Library: kernel32
    * Return value: ATOM

Parameters::

    ** LPCSTR lpString


FindAtomW
=========

Signature::

    * Library: kernel32
    * Return value: ATOM

Parameters::

    ** LPCWSTR lpString


GetAtomNameA
============

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** ATOM nAtom
    ** LPSTR lpBuffer
    ** int nSize


GetAtomNameW
============

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** ATOM nAtom
    ** LPWSTR lpBuffer
    ** int nSize


GetProfileIntA
==============

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPCSTR lpAppName
    ** LPCSTR lpKeyName
    ** INT nDefault


GetProfileIntW
==============

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPCWSTR lpAppName
    ** LPCWSTR lpKeyName
    ** INT nDefault


GetProfileStringA
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpAppName
    ** LPCSTR lpKeyName
    ** LPCSTR lpDefault
    ** LPSTR lpReturnedString
    ** DWORD nSize


GetProfileStringW
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpAppName
    ** LPCWSTR lpKeyName
    ** LPCWSTR lpDefault
    ** LPWSTR lpReturnedString
    ** DWORD nSize


WriteProfileStringA
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpAppName
    ** LPCSTR lpKeyName
    ** LPCSTR lpString


WriteProfileStringW
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpAppName
    ** LPCWSTR lpKeyName
    ** LPCWSTR lpString


GetProfileSectionA
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpAppName
    ** LPSTR lpReturnedString
    ** DWORD nSize


GetProfileSectionW
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpAppName
    ** LPWSTR lpReturnedString
    ** DWORD nSize


WriteProfileSectionA
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpAppName
    ** LPCSTR lpString


WriteProfileSectionW
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpAppName
    ** LPCWSTR lpString


GetPrivateProfileIntA
=====================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPCSTR lpAppName
    ** LPCSTR lpKeyName
    ** INT nDefault
    ** LPCSTR lpFileName


GetPrivateProfileIntW
=====================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPCWSTR lpAppName
    ** LPCWSTR lpKeyName
    ** INT nDefault
    ** LPCWSTR lpFileName


GetPrivateProfileStringA
========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpAppName
    ** LPCSTR lpKeyName
    ** LPCSTR lpDefault
    ** LPSTR lpReturnedString
    ** DWORD nSize
    ** LPCSTR lpFileName


GetPrivateProfileStringW
========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpAppName
    ** LPCWSTR lpKeyName
    ** LPCWSTR lpDefault
    ** LPWSTR lpReturnedString
    ** DWORD nSize
    ** LPCWSTR lpFileName


WritePrivateProfileStringA
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpAppName
    ** LPCSTR lpKeyName
    ** LPCSTR lpString
    ** LPCSTR lpFileName


WritePrivateProfileStringW
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpAppName
    ** LPCWSTR lpKeyName
    ** LPCWSTR lpString
    ** LPCWSTR lpFileName


GetPrivateProfileSectionA
=========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpAppName
    ** LPSTR lpReturnedString
    ** DWORD nSize
    ** LPCSTR lpFileName


GetPrivateProfileSectionW
=========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpAppName
    ** LPWSTR lpReturnedString
    ** DWORD nSize
    ** LPCWSTR lpFileName


WritePrivateProfileSectionA
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpAppName
    ** LPCSTR lpString
    ** LPCSTR lpFileName


WritePrivateProfileSectionW
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpAppName
    ** LPCWSTR lpString
    ** LPCWSTR lpFileName


GetPrivateProfileSectionNamesA
==============================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPSTR lpszReturnBuffer
    ** DWORD nSize
    ** LPCSTR lpFileName


GetPrivateProfileSectionNamesW
==============================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPWSTR lpszReturnBuffer
    ** DWORD nSize
    ** LPCWSTR lpFileName


GetPrivateProfileStructA
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszSection
    ** LPCSTR lpszKey
    ** LPVOID lpStruct
    ** UINT uSizeStruct
    ** LPCSTR szFile


GetPrivateProfileStructW
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszSection
    ** LPCWSTR lpszKey
    ** LPVOID lpStruct
    ** UINT uSizeStruct
    ** LPCWSTR szFile


WritePrivateProfileStructA
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszSection
    ** LPCSTR lpszKey
    ** LPVOID lpStruct
    ** UINT uSizeStruct
    ** LPCSTR szFile


WritePrivateProfileStructW
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszSection
    ** LPCWSTR lpszKey
    ** LPVOID lpStruct
    ** UINT uSizeStruct
    ** LPCWSTR szFile


GetTempPathA
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPSTR lpBuffer


GetTempFileNameA
================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPCSTR lpPathName
    ** LPCSTR lpPrefixString
    ** UINT uUnique
    ** LPSTR lpTempFileName


GetSystemWow64DirectoryA
========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPSTR lpBuffer
    ** UINT uSize


GetSystemWow64DirectoryW
========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPWSTR lpBuffer
    ** UINT uSize


Wow64EnableWow64FsRedirection
=============================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    ** BOOLEAN Wow64FsEnableRedirection


SetDllDirectoryA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpPathName


SetDllDirectoryW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpPathName


GetDllDirectoryA
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPSTR lpBuffer


GetDllDirectoryW
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPWSTR lpBuffer


SetSearchPathMode
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD Flags


CreateDirectoryExA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpTemplateDirectory
    ** LPCSTR lpNewDirectory
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateDirectoryExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpTemplateDirectory
    ** LPCWSTR lpNewDirectory
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateDirectoryTransactedA
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpTemplateDirectory
    ** LPCSTR lpNewDirectory
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** HANDLE hTransaction


CreateDirectoryTransactedW
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpTemplateDirectory
    ** LPCWSTR lpNewDirectory
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** HANDLE hTransaction


RemoveDirectoryTransactedA
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpPathName
    ** HANDLE hTransaction


RemoveDirectoryTransactedW
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpPathName
    ** HANDLE hTransaction


GetFullPathNameTransactedA
==========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpFileName
    ** DWORD nBufferLength
    ** LPSTR lpBuffer
    ** LPSTR *lpFilePart
    ** HANDLE hTransaction


GetFullPathNameTransactedW
==========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD nBufferLength
    ** LPWSTR lpBuffer
    ** LPWSTR *lpFilePart
    ** HANDLE hTransaction


DefineDosDeviceA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** LPCSTR lpDeviceName
    ** LPCSTR lpTargetPath


QueryDosDeviceA
===============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpDeviceName
    ** LPSTR lpTargetPath
    ** DWORD ucchMax


CreateFileTransactedA
=====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCSTR lpFileName
    ** DWORD dwDesiredAccess
    ** DWORD dwShareMode
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** DWORD dwCreationDisposition
    ** DWORD dwFlagsAndAttributes
    ** HANDLE hTemplateFile
    ** HANDLE hTransaction
    ** PUSHORT pusMiniVersion
    ** PVOID lpExtendedParameter


CreateFileTransactedW
=====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD dwDesiredAccess
    ** DWORD dwShareMode
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** DWORD dwCreationDisposition
    ** DWORD dwFlagsAndAttributes
    ** HANDLE hTemplateFile
    ** HANDLE hTransaction
    ** PUSHORT pusMiniVersion
    ** PVOID lpExtendedParameter


ReOpenFile
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** HANDLE hOriginalFile
    ** DWORD dwDesiredAccess
    ** DWORD dwShareMode
    ** DWORD dwFlagsAndAttributes


SetFileAttributesTransactedA
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** DWORD dwFileAttributes
    ** HANDLE hTransaction


SetFileAttributesTransactedW
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD dwFileAttributes
    ** HANDLE hTransaction


GetFileAttributesTransactedA
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** GET_FILEEX_INFO_LEVELS fInfoLevelId
    ** LPVOID lpFileInformation
    ** HANDLE hTransaction


GetFileAttributesTransactedW
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** GET_FILEEX_INFO_LEVELS fInfoLevelId
    ** LPVOID lpFileInformation
    ** HANDLE hTransaction


GetCompressedFileSizeTransactedA
================================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpFileName
    ** LPDWORD lpFileSizeHigh
    ** HANDLE hTransaction


GetCompressedFileSizeTransactedW
================================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** LPDWORD lpFileSizeHigh
    ** HANDLE hTransaction


DeleteFileTransactedA
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** HANDLE hTransaction


DeleteFileTransactedW
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** HANDLE hTransaction


CheckNameLegalDOS8Dot3A
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpName
    ** LPSTR lpOemName
    ** DWORD OemNameSize
    ** PBOOL pbNameContainsSpaces OPTIONAL
    ** PBOOL pbNameLegal


CheckNameLegalDOS8Dot3W
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpName
    ** LPSTR lpOemName
    ** DWORD OemNameSize
    ** PBOOL pbNameContainsSpaces OPTIONAL
    ** PBOOL pbNameLegal


FindFirstFileTransactedA
========================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCSTR lpFileName
    ** FINDEX_INFO_LEVELS fInfoLevelId
    ** LPVOID lpFindFileData
    ** FINDEX_SEARCH_OPS fSearchOp
    ** LPVOID lpSearchFilter
    ** DWORD dwAdditionalFlags
    ** HANDLE hTransaction


FindFirstFileTransactedW
========================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpFileName
    ** FINDEX_INFO_LEVELS fInfoLevelId
    ** LPVOID lpFindFileData
    ** FINDEX_SEARCH_OPS fSearchOp
    ** LPVOID lpSearchFilter
    ** DWORD dwAdditionalFlags
    ** HANDLE hTransaction


CopyFileA
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpExistingFileName
    ** LPCSTR lpNewFileName
    ** BOOL bFailIfExists


CopyFileW
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpExistingFileName
    ** LPCWSTR lpNewFileName
    ** BOOL bFailIfExists


CopyFileExA
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpExistingFileName
    ** LPCSTR lpNewFileName
    ** LPPROGRESS_ROUTINE lpProgressRoutine
    ** LPVOID lpData
    ** LPBOOL pbCancel
    ** DWORD dwCopyFlags


CopyFileExW
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpExistingFileName
    ** LPCWSTR lpNewFileName
    ** LPPROGRESS_ROUTINE lpProgressRoutine
    ** LPVOID lpData
    ** LPBOOL pbCancel
    ** DWORD dwCopyFlags


CopyFileTransactedA
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpExistingFileName
    ** LPCSTR lpNewFileName
    ** LPPROGRESS_ROUTINE lpProgressRoutine
    ** LPVOID lpData
    ** LPBOOL pbCancel
    ** DWORD dwCopyFlags
    ** HANDLE hTransaction


CopyFileTransactedW
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpExistingFileName
    ** LPCWSTR lpNewFileName
    ** LPPROGRESS_ROUTINE lpProgressRoutine
    ** LPVOID lpData
    ** LPBOOL pbCancel
    ** DWORD dwCopyFlags
    ** HANDLE hTransaction


CopyFile2
=========

Signature::

    * Library: 
    * Return value: HRESULT

Parameters::

    ** PCWSTR pwszExistingFileName
    ** PCWSTR pwszNewFileName
    ** COPYFILE2_EXTENDED_PARAMETERS *pExtendedParameters


MoveFileA
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpExistingFileName
    ** LPCSTR lpNewFileName


MoveFileW
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpExistingFileName
    ** LPCWSTR lpNewFileName


MoveFileExA
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpExistingFileName
    ** LPCSTR lpNewFileName
    ** DWORD dwFlags


MoveFileExW
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpExistingFileName
    ** LPCWSTR lpNewFileName
    ** DWORD dwFlags


MoveFileWithProgressA
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpExistingFileName
    ** LPCSTR lpNewFileName
    ** LPPROGRESS_ROUTINE lpProgressRoutine
    ** LPVOID lpData
    ** DWORD dwFlags


MoveFileWithProgressW
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpExistingFileName
    ** LPCWSTR lpNewFileName
    ** LPPROGRESS_ROUTINE lpProgressRoutine
    ** LPVOID lpData
    ** DWORD dwFlags


MoveFileTransactedA
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpExistingFileName
    ** LPCSTR lpNewFileName
    ** LPPROGRESS_ROUTINE lpProgressRoutine
    ** LPVOID lpData
    ** DWORD dwFlags
    ** HANDLE hTransaction


MoveFileTransactedW
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpExistingFileName
    ** LPCWSTR lpNewFileName
    ** LPPROGRESS_ROUTINE lpProgressRoutine
    ** LPVOID lpData
    ** DWORD dwFlags
    ** HANDLE hTransaction


ReplaceFileA
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpReplacedFileName
    ** LPCSTR lpReplacementFileName
    ** LPCSTR lpBackupFileName
    ** DWORD dwReplaceFlags
    ** LPVOID lpExclude
    ** LPVOID lpReserved


ReplaceFileW
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpReplacedFileName
    ** LPCWSTR lpReplacementFileName
    ** LPCWSTR lpBackupFileName
    ** DWORD dwReplaceFlags
    ** LPVOID lpExclude
    ** LPVOID lpReserved


CreateHardLinkA
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** LPCSTR lpExistingFileName
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateHardLinkW
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** LPCWSTR lpExistingFileName
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateHardLinkTransactedA
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** LPCSTR lpExistingFileName
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** HANDLE hTransaction


CreateHardLinkTransactedW
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** LPCWSTR lpExistingFileName
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** HANDLE hTransaction


FindFirstStreamW
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpFileName
    ** STREAM_INFO_LEVELS InfoLevel
    ** LPVOID lpFindStreamData
    ** DWORD dwFlags


FindFirstStreamTransactedW
==========================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpFileName
    ** STREAM_INFO_LEVELS InfoLevel
    ** LPVOID lpFindStreamData
    ** DWORD dwFlags
    ** HANDLE hTransaction


FindNextStreamW
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindStream
    ** LPVOID lpFindStreamData


FindFirstFileNameW
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD dwFlags
    ** LPDWORD StringLength
    ** PWSTR LinkName


FindNextFileNameW
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindStream
    ** LPDWORD StringLength
    ** PWSTR LinkName


FindFirstFileNameTransactedW
============================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD dwFlags
    ** LPDWORD StringLength
    ** PWSTR LinkName
    ** HANDLE hTransaction


CreateNamedPipeA
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCSTR lpName
    ** DWORD dwOpenMode
    ** DWORD dwPipeMode
    ** DWORD nMaxInstances
    ** DWORD nOutBufferSize
    ** DWORD nInBufferSize
    ** DWORD nDefaultTimeOut
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes


GetNamedPipeHandleStateA
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hNamedPipe
    ** LPDWORD lpState
    ** LPDWORD lpCurInstances
    ** LPDWORD lpMaxCollectionCount
    ** LPDWORD lpCollectDataTimeout
    ** LPSTR lpUserName
    ** DWORD nMaxUserNameSize


GetNamedPipeHandleStateW
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hNamedPipe
    ** LPDWORD lpState
    ** LPDWORD lpCurInstances
    ** LPDWORD lpMaxCollectionCount
    ** LPDWORD lpCollectDataTimeout
    ** LPWSTR lpUserName
    ** DWORD nMaxUserNameSize


CallNamedPipeA
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpNamedPipeName
    ** LPVOID lpInBuffer
    ** DWORD nInBufferSize
    ** LPVOID lpOutBuffer
    ** DWORD nOutBufferSize
    ** LPDWORD lpBytesRead
    ** DWORD nTimeOut


CallNamedPipeW
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpNamedPipeName
    ** LPVOID lpInBuffer
    ** DWORD nInBufferSize
    ** LPVOID lpOutBuffer
    ** DWORD nOutBufferSize
    ** LPDWORD lpBytesRead
    ** DWORD nTimeOut


WaitNamedPipeA
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpNamedPipeName
    ** DWORD nTimeOut


GetNamedPipeClientComputerNameA
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE Pipe
    ** LPSTR ClientComputerName
    ** ULONG ClientComputerNameLength


GetNamedPipeClientProcessId
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE Pipe
    ** PULONG ClientProcessId


GetNamedPipeClientSessionId
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE Pipe
    ** PULONG ClientSessionId


GetNamedPipeServerProcessId
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE Pipe
    ** PULONG ServerProcessId


GetNamedPipeServerSessionId
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE Pipe
    ** PULONG ServerSessionId


SetVolumeLabelA
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpRootPathName
    ** LPCSTR lpVolumeName


SetVolumeLabelW
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpRootPathName
    ** LPCWSTR lpVolumeName


GetVolumeInformationA
=====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPCSTR lpRootPathName
    ** LPSTR lpVolumeNameBuffer
    ** DWORD nVolumeNameSize
    ** LPDWORD lpVolumeSerialNumber
    ** LPDWORD lpMaximumComponentLength
    ** LPDWORD lpFileSystemFlags
    ** LPSTR lpFileSystemNameBuffer
    ** DWORD nFileSystemNameSize


SetFileBandwidthReservation
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** DWORD nPeriodMilliseconds
    ** DWORD nBytesPerPeriod
    ** BOOL bDiscardable
    ** LPDWORD lpTransferSize
    ** LPDWORD lpNumOutstandingRequests


GetFileBandwidthReservation
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPDWORD lpPeriodMilliseconds
    ** LPDWORD lpBytesPerPeriod
    ** LPBOOL pDiscardable
    ** LPDWORD lpTransferSize
    ** LPDWORD lpNumOutstandingRequests


ReadDirectoryChangesW
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hDirectory
    ** LPVOID lpBuffer
    ** DWORD nBufferLength
    ** BOOL bWatchSubtree
    ** DWORD dwNotifyFilter
    ** LPDWORD lpBytesReturned
    ** LPOVERLAPPED lpOverlapped
    ** LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


MapViewOfFileExNuma
===================

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** HANDLE hFileMappingObject
    ** DWORD dwDesiredAccess
    ** DWORD dwFileOffsetHigh
    ** DWORD dwFileOffsetLow
    ** SIZE_T dwNumberOfBytesToMap
    ** LPVOID lpBaseAddress
    ** DWORD nndPreferred


IsBadReadPtr
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** void *lp
    ** UINT_PTR ucb


IsBadWritePtr
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPVOID lp
    ** UINT_PTR ucb


IsBadHugeReadPtr
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** void *lp
    ** UINT_PTR ucb


IsBadHugeWritePtr
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPVOID lp
    ** UINT_PTR ucb


IsBadCodePtr
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** FARPROC lpfn


IsBadStringPtrA
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpsz
    ** UINT_PTR ucchMax


IsBadStringPtrW
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpsz
    ** UINT_PTR ucchMax


BuildCommDCBA
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpDef
    ** LPDCB lpDCB


BuildCommDCBW
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpDef
    ** LPDCB lpDCB


BuildCommDCBAndTimeoutsA
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpDef
    ** LPDCB lpDCB
    ** LPCOMMTIMEOUTS lpCommTimeouts


BuildCommDCBAndTimeoutsW
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpDef
    ** LPDCB lpDCB
    ** LPCOMMTIMEOUTS lpCommTimeouts


CommConfigDialogA
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszName
    ** HWND hWnd
    ** LPCOMMCONFIG lpCC


CommConfigDialogW
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszName
    ** HWND hWnd
    ** LPCOMMCONFIG lpCC


GetDefaultCommConfigA
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszName
    ** LPCOMMCONFIG lpCC
    ** LPDWORD lpdwSize


GetDefaultCommConfigW
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszName
    ** LPCOMMCONFIG lpCC
    ** LPDWORD lpdwSize


SetDefaultCommConfigA
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszName
    ** LPCOMMCONFIG lpCC
    ** DWORD dwSize


SetDefaultCommConfigW
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszName
    ** LPCOMMCONFIG lpCC
    ** DWORD dwSize


GetComputerNameA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPSTR lpBuffer
    ** LPDWORD nSize


GetComputerNameW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPWSTR lpBuffer
    ** LPDWORD nSize


SetComputerNameA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpComputerName


SetComputerNameW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpComputerName


SetComputerNameExA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** COMPUTER_NAME_FORMAT NameType
    ** LPCSTR lpBuffer


DnsHostnameToComputerNameA
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR Hostname
    ** LPSTR ComputerName
    ** LPDWORD nSize


DnsHostnameToComputerNameW
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR Hostname
    ** LPWSTR ComputerName
    ** LPDWORD nSize


RegisterWaitForSingleObject
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PHANDLE phNewWaitObject
    ** HANDLE hObject
    ** WAITORTIMERCALLBACK Callback
    ** PVOID Context
    ** ULONG dwMilliseconds
    ** ULONG dwFlags


UnregisterWait
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE WaitHandle


BindIoCompletionCallback
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE FileHandle
    ** LPOVERLAPPED_COMPLETION_ROUTINE Function
    ** ULONG Flags


SetTimerQueueTimer
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** HANDLE TimerQueue
    ** WAITORTIMERCALLBACK Callback
    ** PVOID Parameter
    ** DWORD DueTime
    ** DWORD Period
    ** BOOL PreferIo


CancelTimerQueueTimer
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE TimerQueue
    ** HANDLE Timer


DeleteTimerQueue
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE TimerQueue


CreatePrivateNamespaceA
=======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpPrivateNamespaceAttributes
    ** LPVOID lpBoundaryDescriptor
    ** LPCSTR lpAliasPrefix


OpenPrivateNamespaceA
=====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPVOID lpBoundaryDescriptor
    ** LPCSTR lpAliasPrefix


CreateBoundaryDescriptorA
=========================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCSTR Name
    ** ULONG Flags


AddIntegrityLabelToBoundaryDescriptor
=====================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE *BoundaryDescriptor
    ** PSID IntegrityLabel


VerifyVersionInfoA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPOSVERSIONINFOEXA lpVersionInformation
    ** DWORD dwTypeMask
    ** DWORDLONG dwlConditionMask


VerifyVersionInfoW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPOSVERSIONINFOEXW lpVersionInformation
    ** DWORD dwTypeMask
    ** DWORDLONG dwlConditionMask


GetSystemPowerStatus
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPSYSTEM_POWER_STATUS lpSystemPowerStatus


SetSystemPowerState
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** BOOL fSuspend
    ** BOOL fForce


MapUserPhysicalPagesScatter
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PVOID *VirtualAddresses
    ** ULONG_PTR NumberOfPages
    ** PULONG_PTR PageArray


CreateJobObjectA
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpJobAttributes
    ** LPCSTR lpName


CreateJobObjectW
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpJobAttributes
    ** LPCWSTR lpName


OpenJobObjectA
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCSTR lpName


OpenJobObjectW
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCWSTR lpName


AssignProcessToJobObject
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hJob
    ** HANDLE hProcess


TerminateJobObject
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hJob
    ** UINT uExitCode


QueryInformationJobObject
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hJob
    ** JOBOBJECTINFOCLASS JobObjectInformationClass
    ** LPVOID lpJobObjectInformation
    ** DWORD cbJobObjectInformationLength
    ** LPDWORD lpReturnLength


SetInformationJobObject
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hJob
    ** JOBOBJECTINFOCLASS JobObjectInformationClass
    ** LPVOID lpJobObjectInformation
    ** DWORD cbJobObjectInformationLength


CreateJobSet
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** ULONG NumJob
    ** PJOB_SET_ARRAY UserJobSet
    ** ULONG Flags


FindFirstVolumeA
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSTR lpszVolumeName
    ** DWORD cchBufferLength


FindNextVolumeA
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindVolume
    ** LPSTR lpszVolumeName
    ** DWORD cchBufferLength


FindFirstVolumeMountPointA
==========================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCSTR lpszRootPathName
    ** LPSTR lpszVolumeMountPoint
    ** DWORD cchBufferLength


FindFirstVolumeMountPointW
==========================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpszRootPathName
    ** LPWSTR lpszVolumeMountPoint
    ** DWORD cchBufferLength


FindNextVolumeMountPointA
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindVolumeMountPoint
    ** LPSTR lpszVolumeMountPoint
    ** DWORD cchBufferLength


FindNextVolumeMountPointW
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindVolumeMountPoint
    ** LPWSTR lpszVolumeMountPoint
    ** DWORD cchBufferLength


FindVolumeMountPointClose
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindVolumeMountPoint


SetVolumeMountPointA
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszVolumeMountPoint
    ** LPCSTR lpszVolumeName


SetVolumeMountPointW
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszVolumeMountPoint
    ** LPCWSTR lpszVolumeName


DeleteVolumeMountPointA
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszVolumeMountPoint


GetVolumeNameForVolumeMountPointA
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszVolumeMountPoint
    ** LPSTR lpszVolumeName
    ** DWORD cchBufferLength


GetVolumePathNameA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszFileName
    ** LPSTR lpszVolumePathName
    ** DWORD cchBufferLength


GetVolumePathNamesForVolumeNameA
================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszVolumeName
    ** LPCH lpszVolumePathNames
    ** DWORD cchBufferLength
    ** PDWORD lpcchReturnLength


CreateActCtxA
=============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** PCACTCTXA pActCtx


CreateActCtxW
=============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** PCACTCTXW pActCtx


AddRefActCtx
============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** HANDLE hActCtx


ReleaseActCtx
=============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** HANDLE hActCtx


ZombifyActCtx
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hActCtx


ActivateActCtx
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hActCtx
    ** ULONG_PTR *lpCookie


DeactivateActCtx
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** ULONG_PTR ulCookie


GetCurrentActCtx
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE *lphActCtx


FindActCtxSectionStringA
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** const GUID *lpExtensionGuid
    ** ULONG ulSectionId
    ** LPCSTR lpStringToFind
    ** PACTCTX_SECTION_KEYED_DATA ReturnedData


FindActCtxSectionStringW
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** const GUID *lpExtensionGuid
    ** ULONG ulSectionId
    ** LPCWSTR lpStringToFind
    ** PACTCTX_SECTION_KEYED_DATA ReturnedData


FindActCtxSectionGuid
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** const GUID *lpExtensionGuid
    ** ULONG ulSectionId
    ** const GUID *lpGuidToFind
    ** PACTCTX_SECTION_KEYED_DATA ReturnedData


QueryActCtxW
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** HANDLE hActCtx
    ** PVOID pvSubInstance
    ** ULONG ulInfoClass
    ** PVOID pvBuffer
    ** SIZE_T cbBuffer
    ** SIZE_T *pcbWrittenOrRequired


WTSGetActiveConsoleSessionId
============================

Signature::

    * Library: kernel32
    * Return value: DWORD


GetActiveProcessorGroupCount
============================

Signature::

    * Library: kernel32
    * Return value: WORD


GetMaximumProcessorGroupCount
=============================

Signature::

    * Library: kernel32
    * Return value: WORD


GetActiveProcessorCount
=======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** WORD GroupNumber


GetMaximumProcessorCount
========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** WORD GroupNumber


GetNumaProcessorNode
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UCHAR Processor
    ** PUCHAR NodeNumber


GetNumaNodeNumberFromHandle
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** PUSHORT NodeNumber


GetNumaProcessorNodeEx
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PPROCESSOR_NUMBER Processor
    ** PUSHORT NodeNumber


GetNumaNodeProcessorMask
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UCHAR Node
    ** PULONGLONG ProcessorMask


GetNumaAvailableMemoryNode
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UCHAR Node
    ** PULONGLONG AvailableBytes


GetNumaAvailableMemoryNodeEx
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** USHORT Node
    ** PULONGLONG AvailableBytes


GetNumaProximityNode
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** ULONG ProximityId
    ** PUCHAR NodeNumber


GetNumaProximityNodeEx
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** ULONG ProximityId
    ** PUSHORT NodeNumber


RegisterApplicationRecoveryCallback
===================================

Signature::

    * Library: kernel32
    * Return value: HRESULT

Parameters::

    ** APPLICATION_RECOVERY_CALLBACK pRecoveyCallback
    ** PVOID pvParameter
    ** DWORD dwPingInterval
    ** DWORD dwFlags


RegisterApplicationRestart
==========================

Signature::

    * Library: kernel32
    * Return value: HRESULT

Parameters::

    ** PCWSTR pwzCommandline
    ** DWORD dwFlags


GetApplicationRecoveryCallback
==============================

Signature::

    * Library: kernel32
    * Return value: HRESULT

Parameters::

    ** HANDLE hProcess
    ** APPLICATION_RECOVERY_CALLBACK *pRecoveryCallback
    ** PVOID *ppvParameter
    ** PDWORD pdwPingInterval
    ** PDWORD pdwFlags


GetApplicationRestartSettings
=============================

Signature::

    * Library: kernel32
    * Return value: HRESULT

Parameters::

    ** HANDLE hProcess
    ** PWSTR pwzCommandline
    ** PDWORD pcchSize
    ** PDWORD pdwFlags


ApplicationRecoveryInProgress
=============================

Signature::

    * Library: kernel32
    * Return value: HRESULT

Parameters::

    ** PBOOL pbCancelled


ApplicationRecoveryFinished
===========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** BOOL bSuccess


GetFileInformationByHandleEx
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** FILE_INFO_BY_HANDLE_CLASS FileInformationClass
    ** LPVOID lpFileInformation
    ** DWORD dwBufferSize


OpenFileById
============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** HANDLE hVolumeHint
    ** LPFILE_ID_DESCRIPTOR lpFileId
    ** DWORD dwDesiredAccess
    ** DWORD dwShareMode
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** DWORD dwFlagsAndAttributes


CreateSymbolicLinkA
===================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    ** LPCSTR lpSymlinkFileName
    ** LPCSTR lpTargetFileName
    ** DWORD dwFlags


CreateSymbolicLinkW
===================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    ** LPCWSTR lpSymlinkFileName
    ** LPCWSTR lpTargetFileName
    ** DWORD dwFlags


CreateSymbolicLinkTransactedA
=============================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    ** LPCSTR lpSymlinkFileName
    ** LPCSTR lpTargetFileName
    ** DWORD dwFlags
    ** HANDLE hTransaction


CreateSymbolicLinkTransactedW
=============================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    ** LPCWSTR lpSymlinkFileName
    ** LPCWSTR lpTargetFileName
    ** DWORD dwFlags
    ** HANDLE hTransaction


QueryActCtxSettingsW
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** HANDLE hActCtx
    ** PCWSTR settingsNameSpace
    ** PCWSTR settingName
    ** PWSTR pvBuffer
    ** SIZE_T dwBuffer
    ** SIZE_T *pdwWrittenOrRequired


ReplacePartitionUnit
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PWSTR TargetPartition
    ** PWSTR SparePartition
    ** ULONG Flags


AddSecureMemoryCacheCallback
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PSECURE_MEMORY_CACHE_CALLBACK pfnCallBack


RemoveSecureMemoryCacheCallback
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PSECURE_MEMORY_CACHE_CALLBACK pfnCallBack


CopyContext
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PCONTEXT Destination
    ** DWORD ContextFlags
    ** PCONTEXT Source


InitializeContext
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PVOID Buffer
    ** DWORD ContextFlags
    ** PCONTEXT *Context
    ** PDWORD ContextLength


GetEnabledXStateFeatures
========================

Signature::

    * Library: kernel32
    * Return value: DWORD64


GetXStateFeaturesMask
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PCONTEXT Context
    ** PDWORD64 FeatureMask


LocateXStateFeature
===================

Signature::

    * Library: kernel32
    * Return value: PVOID

Parameters::

    ** PCONTEXT Context
    ** DWORD FeatureId
    ** PDWORD Length


SetXStateFeaturesMask
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PCONTEXT Context
    ** DWORD64 FeatureMask


EnableThreadProfiling
=====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE ThreadHandle
    ** DWORD Flags
    ** DWORD64 HardwareCounters
    ** HANDLE *PerformanceDataHandle


DisableThreadProfiling
======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE PerformanceDataHandle


QueryThreadProfiling
====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE ThreadHandle
    ** PBOOLEAN Enabled


ReadThreadProfilingData
=======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE PerformanceDataHandle
    ** DWORD Flags
    ** PPERFORMANCE_DATA PerformanceData


PeekConsoleInputW
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleInput
    ** PINPUT_RECORD lpBuffer
    ** DWORD nLength
    ** LPDWORD lpNumberOfEventsRead


WriteConsoleInputA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleInput
    ** INPUT_RECORD *lpBuffer
    ** DWORD nLength
    ** LPDWORD lpNumberOfEventsWritten


WriteConsoleInputW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleInput
    ** INPUT_RECORD *lpBuffer
    ** DWORD nLength
    ** LPDWORD lpNumberOfEventsWritten


ReadConsoleOutputA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** PCHAR_INFO lpBuffer
    ** COORD dwBufferSize
    ** COORD dwBufferCoord
    ** PSMALL_RECT lpReadRegion


ReadConsoleOutputW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** PCHAR_INFO lpBuffer
    ** COORD dwBufferSize
    ** COORD dwBufferCoord
    ** PSMALL_RECT lpReadRegion


WriteConsoleOutputA
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** CHAR_INFO *lpBuffer
    ** COORD dwBufferSize
    ** COORD dwBufferCoord
    ** PSMALL_RECT lpWriteRegion


WriteConsoleOutputW
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** CHAR_INFO *lpBuffer
    ** COORD dwBufferSize
    ** COORD dwBufferCoord
    ** PSMALL_RECT lpWriteRegion


ReadConsoleOutputCharacterA
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** LPSTR lpCharacter
    ** DWORD nLength
    ** COORD dwReadCoord
    ** LPDWORD lpNumberOfCharsRead


ReadConsoleOutputCharacterW
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** LPWSTR lpCharacter
    ** DWORD nLength
    ** COORD dwReadCoord
    ** LPDWORD lpNumberOfCharsRead


ReadConsoleOutputAttribute
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** LPWORD lpAttribute
    ** DWORD nLength
    ** COORD dwReadCoord
    ** LPDWORD lpNumberOfAttrsRead


WriteConsoleOutputCharacterA
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** LPCSTR lpCharacter
    ** DWORD nLength
    ** COORD dwWriteCoord
    ** LPDWORD lpNumberOfCharsWritten


WriteConsoleOutputCharacterW
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** LPCWSTR lpCharacter
    ** DWORD nLength
    ** COORD dwWriteCoord
    ** LPDWORD lpNumberOfCharsWritten


WriteConsoleOutputAttribute
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** WORD *lpAttribute
    ** DWORD nLength
    ** COORD dwWriteCoord
    ** LPDWORD lpNumberOfAttrsWritten


FillConsoleOutputCharacterA
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** CHAR cCharacter
    ** DWORD nLength
    ** COORD dwWriteCoord
    ** LPDWORD lpNumberOfCharsWritten


FillConsoleOutputCharacterW
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** WCHAR cCharacter
    ** DWORD nLength
    ** COORD dwWriteCoord
    ** LPDWORD lpNumberOfCharsWritten


FillConsoleOutputAttribute
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** WORD wAttribute
    ** DWORD nLength
    ** COORD dwWriteCoord
    ** LPDWORD lpNumberOfAttrsWritten


GetConsoleScreenBufferInfo
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo


GetConsoleScreenBufferInfoEx
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** PCONSOLE_SCREEN_BUFFER_INFOEX lpConsoleScreenBufferInfoEx


SetConsoleScreenBufferInfoEx
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** PCONSOLE_SCREEN_BUFFER_INFOEX lpConsoleScreenBufferInfoEx


_GetLargestConsoleWindowSize
============================

Signature::

    * Library: kernel32
    * Return value: COORD

Parameters::

    ** HANDLE hConsoleOutput


GetConsoleCursorInfo
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** PCONSOLE_CURSOR_INFO lpConsoleCursorInfo


GetCurrentConsoleFont
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** BOOL bMaximumWindow
    ** PCONSOLE_FONT_INFO lpConsoleCurrentFont


GetCurrentConsoleFontEx
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** BOOL bMaximumWindow
    ** PCONSOLE_FONT_INFOEX lpConsoleCurrentFontEx


SetCurrentConsoleFontEx
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** BOOL bMaximumWindow
    ** PCONSOLE_FONT_INFOEX lpConsoleCurrentFontEx


GetConsoleHistoryInfo
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PCONSOLE_HISTORY_INFO lpConsoleHistoryInfo


SetConsoleHistoryInfo
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PCONSOLE_HISTORY_INFO lpConsoleHistoryInfo


_GetConsoleFontSize
===================

Signature::

    * Library: kernel32
    * Return value: COORD

Parameters::

    ** HANDLE hConsoleOutput
    ** DWORD nFont


GetConsoleSelectionInfo
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PCONSOLE_SELECTION_INFO lpConsoleSelectionInfo


GetNumberOfConsoleMouseButtons
==============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPDWORD lpNumberOfMouseButtons


SetConsoleActiveScreenBuffer
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput


FlushConsoleInputBuffer
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleInput


SetConsoleScreenBufferSize
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** COORD dwSize


SetConsoleCursorPosition
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** COORD dwCursorPosition


SetConsoleCursorInfo
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** CONSOLE_CURSOR_INFO *lpConsoleCursorInfo


ScrollConsoleScreenBufferA
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** SMALL_RECT *lpScrollRectangle
    ** SMALL_RECT *lpClipRectangle
    ** COORD dwDestinationOrigin
    ** CHAR_INFO *lpFill


ScrollConsoleScreenBufferW
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** SMALL_RECT *lpScrollRectangle
    ** SMALL_RECT *lpClipRectangle
    ** COORD dwDestinationOrigin
    ** CHAR_INFO *lpFill


SetConsoleWindowInfo
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** BOOL bAbsolute
    ** SMALL_RECT *lpConsoleWindow


SetConsoleTextAttribute
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** WORD wAttributes


GenerateConsoleCtrlEvent
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwCtrlEvent
    ** DWORD dwProcessGroupId


FreeConsole
===========

Signature::

    * Library: kernel32
    * Return value: BOOL


AttachConsole
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwProcessId


GetConsoleTitleA
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPSTR lpConsoleTitle
    ** DWORD nSize


GetConsoleTitleW
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPWSTR lpConsoleTitle
    ** DWORD nSize


GetConsoleOriginalTitleA
========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPSTR lpConsoleTitle
    ** DWORD nSize


GetConsoleOriginalTitleW
========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPWSTR lpConsoleTitle
    ** DWORD nSize


SetConsoleTitleA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpConsoleTitle


SetConsoleTitleW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpConsoleTitle


CreateConsoleScreenBuffer
=========================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** DWORD dwShareMode
    ** SECURITY_ATTRIBUTES *lpSecurityAttributes
    ** DWORD dwFlags
    ** LPVOID lpScreenBufferData


SetConsoleCP
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UINT wCodePageID


SetConsoleOutputCP
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UINT wCodePageID


GetConsoleDisplayMode
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPDWORD lpModeFlags


GetConsoleWindow
================

Signature::

    * Library: kernel32
    * Return value: HWND


GetConsoleProcessList
=====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPDWORD lpdwProcessList
    ** DWORD dwProcessCount


AddConsoleAliasA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPSTR Source
    ** LPSTR Target
    ** LPSTR ExeName


AddConsoleAliasW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPWSTR Source
    ** LPWSTR Target
    ** LPWSTR ExeName


GetConsoleAliasA
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPSTR Source
    ** LPSTR TargetBuffer
    ** DWORD TargetBufferLength
    ** LPSTR ExeName


GetConsoleAliasW
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPWSTR Source
    ** LPWSTR TargetBuffer
    ** DWORD TargetBufferLength
    ** LPWSTR ExeName


GetConsoleAliasesLengthA
========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPSTR ExeName


GetConsoleAliasesLengthW
========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPWSTR ExeName


GetConsoleAliasExesLengthA
==========================

Signature::

    * Library: kernel32
    * Return value: DWORD


GetConsoleAliasExesLengthW
==========================

Signature::

    * Library: kernel32
    * Return value: DWORD


GetConsoleAliasesA
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPSTR AliasBuffer
    ** DWORD AliasBufferLength
    ** LPSTR ExeName


GetConsoleAliasesW
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPWSTR AliasBuffer
    ** DWORD AliasBufferLength
    ** LPWSTR ExeName


GetConsoleAliasExesA
====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPSTR ExeNameBuffer
    ** DWORD ExeNameBufferLength


GetConsoleAliasExesW
====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPWSTR ExeNameBuffer
    ** DWORD ExeNameBufferLength


IsValidCodePage
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UINT CodePage


GetCPInfo
=========

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** UINT CodePage
    ** LPCPINFO lpCPInfo


GetCPInfoExA
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UINT CodePage
    ** DWORD dwFlags
    ** LPCPINFOEXA lpCPInfoEx


GetCPInfoExW
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UINT CodePage
    ** DWORD dwFlags
    ** LPCPINFOEXW lpCPInfoEx


CompareStringA
==============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwCmpFlags
    ** PCNZCH lpString1
    ** int cchCount1
    ** PCNZCH lpString2
    ** int cchCount2


FindNLSString
=============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwFindNLSStringFlags
    ** LPCWSTR lpStringSource
    ** int cchSource
    ** LPCWSTR lpStringValue
    ** int cchValue


LCMapStringW
============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwMapFlags
    ** LPCWSTR lpSrcStr
    ** int cchSrc
    ** LPWSTR lpDestStr
    ** int cchDest


LCMapStringA
============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwMapFlags
    ** LPCSTR lpSrcStr
    ** int cchSrc
    ** LPSTR lpDestStr
    ** int cchDest


GetLocaleInfoW
==============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** LCTYPE LCType
    ** LPWSTR lpLCData
    ** int cchData


GetLocaleInfoA
==============

Signature::

    * Library: kernel32
    * Return value: int 

Parameters::

    ** LCID Locale
    ** LCTYPE LCType
    ** LPSTR lpLCData
    ** int cchData


SetLocaleInfoA
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LCID Locale
    ** LCTYPE LCType
    ** LPCSTR lpLCData


SetLocaleInfoW
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LCID Locale
    ** LCTYPE LCType
    ** LPCWSTR lpLCData


GetCalendarInfoA
================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** CALID Calendar
    ** CALTYPE CalType
    ** LPSTR lpCalData
    ** int cchData


GetCalendarInfoW
================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** CALID Calendar
    ** CALTYPE CalType
    ** LPWSTR lpCalData
    ** int cchData


SetCalendarInfoA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LCID Locale
    ** CALID Calendar
    ** CALTYPE CalType
    ** LPCSTR lpCalData


SetCalendarInfoW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LCID Locale
    ** CALID Calendar
    ** CALTYPE CalType
    ** LPCWSTR lpCalData


IsDBCSLeadByteEx
================

Signature::

    * Library: kernel32
    * Return value: BOOL                                      

Parameters::

    ** UINT CodePage
    ** BYTE TestChar


LCIDToLocaleName
================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** LPWSTR lpName
    ** int cchName
    ** DWORD dwFlags


LocaleNameToLCID
================

Signature::

    * Library: kernel32
    * Return value: LCID

Parameters::

    ** LPCWSTR lpName
    ** DWORD dwFlags


GetDurationFormat
=================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwFlags
    ** SYSTEMTIME *lpDuration
    ** ULONGLONG ullDuration
    ** LPCWSTR lpFormat
    ** LPWSTR lpDurationStr
    ** int cchDuration


GetNumberFormatA
================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwFlags
    ** LPCSTR lpValue
    ** NUMBERFMTA *lpFormat
    ** LPSTR lpNumberStr
    ** int cchNumber


GetNumberFormatW
================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwFlags
    ** LPCWSTR lpValue
    ** NUMBERFMTW *lpFormat
    ** LPWSTR lpNumberStr
    ** int cchNumber


GetCurrencyFormatA
==================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwFlags
    ** LPCSTR lpValue
    ** CURRENCYFMTA *lpFormat
    ** LPSTR lpCurrencyStr
    ** int cchCurrency


GetCurrencyFormatW
==================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwFlags
    ** LPCWSTR lpValue
    ** CURRENCYFMTW *lpFormat
    ** LPWSTR lpCurrencyStr
    ** int cchCurrency


EnumCalendarInfoA
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** CALINFO_ENUMPROCA lpCalInfoEnumProc
    ** LCID Locale
    ** CALID Calendar
    ** CALTYPE CalType


EnumCalendarInfoW
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** CALINFO_ENUMPROCW lpCalInfoEnumProc
    ** LCID Locale
    ** CALID Calendar
    ** CALTYPE CalType


EnumCalendarInfoExA
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** CALINFO_ENUMPROCEXA lpCalInfoEnumProcEx
    ** LCID Locale
    ** CALID Calendar
    ** CALTYPE CalType


EnumCalendarInfoExW
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** CALINFO_ENUMPROCEXW lpCalInfoEnumProcEx
    ** LCID Locale
    ** CALID Calendar
    ** CALTYPE CalType


EnumTimeFormatsA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** TIMEFMT_ENUMPROCA lpTimeFmtEnumProc
    ** LCID Locale
    ** DWORD dwFlags


EnumTimeFormatsW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** TIMEFMT_ENUMPROCW lpTimeFmtEnumProc
    ** LCID Locale
    ** DWORD dwFlags


EnumDateFormatsA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DATEFMT_ENUMPROCA lpDateFmtEnumProc
    ** LCID Locale
    ** DWORD dwFlags


EnumDateFormatsW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DATEFMT_ENUMPROCW lpDateFmtEnumProc
    ** LCID Locale
    ** DWORD dwFlags


EnumDateFormatsExA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DATEFMT_ENUMPROCEXA lpDateFmtEnumProcEx
    ** LCID Locale
    ** DWORD dwFlags


EnumDateFormatsExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DATEFMT_ENUMPROCEXW lpDateFmtEnumProcEx
    ** LCID Locale
    ** DWORD dwFlags


IsValidLanguageGroup
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LGRPID LanguageGroup
    ** DWORD dwFlags


GetNLSVersion
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** NLS_FUNCTION Function
    ** LCID Locale
    ** LPNLSVERSIONINFO lpVersionInformation


IsNLSDefinedString
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** NLS_FUNCTION Function
    ** DWORD dwFlags
    ** LPNLSVERSIONINFO lpVersionInformation
    ** LPCWSTR lpString
    ** INT cchStr


IsValidLocale
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LCID Locale
    ** DWORD dwFlags


GetGeoInfoA
===========

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** GEOID Location
    ** GEOTYPE GeoType
    ** LPSTR lpGeoData
    ** int cchData
    ** LANGID LangId


GetGeoInfoW
===========

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** GEOID Location
    ** GEOTYPE GeoType
    ** LPWSTR lpGeoData
    ** int cchData
    ** LANGID LangId


EnumSystemGeoID
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** GEOCLASS GeoClass
    ** GEOID ParentGeoId
    ** GEO_ENUMPROC lpGeoEnumProc


GetUserGeoID
============

Signature::

    * Library: kernel32
    * Return value: GEOID

Parameters::

    ** GEOCLASS GeoClass


SetUserGeoID
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** GEOID GeoId


ConvertDefaultLocale
====================

Signature::

    * Library: kernel32
    * Return value: LCID

Parameters::

    ** LCID Locale


SetThreadLocale
===============

Signature::

    * Library: kernel32
    * Return value: LCID

Parameters::

    ** LCID Locale


GetProcessPreferredUILanguages
==============================

Signature::

    * Library: kernel32
    * Return value: LANGID

Parameters::

    ** DWORD dwFlags
    ** PULONG pulNumLanguages
    ** PZZWSTR pwszLanguagesBuffer
    ** PULONG pcchLanguagesBuffer


SetProcessPreferredUILanguages
==============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** PCZZWSTR pwszLanguagesBuffer
    ** PULONG pulNumLanguages


GetUserPreferredUILanguages
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** PULONG pulNumLanguages
    ** PZZWSTR pwszLanguagesBuffer
    ** PULONG pcchLanguagesBuffer


GetSystemPreferredUILanguages
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** PULONG pulNumLanguages
    ** PZZWSTR pwszLanguagesBuffer
    ** PULONG pcchLanguagesBuffer


GetThreadPreferredUILanguages
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** PULONG pulNumLanguages
    ** PZZWSTR pwszLanguagesBuffer
    ** PULONG pcchLanguagesBuffer


SetThreadPreferredUILanguages
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** PCZZWSTR pwszLanguagesBuffer
    ** PULONG pulNumLanguages


GetFileMUIInfo
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** PCWSTR pcwszFilePath
    ** PFILEMUIINFO pFileMUIInfo
    ** DWORD *pcbFileMUIInfo


GetFileMUIPath
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** PCWSTR pcwszFilePath
    ** PWSTR pwszLanguage
    ** PULONG pcchLanguage
    ** PWSTR pwszFileMUIPath
    ** PULONG pcchFileMUIPath
    ** PULONGLONG pululEnumerator


GetUILanguageInfo
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** PCZZWSTR pwmszLanguage
    ** PZZWSTR pwszFallbackLanguages
    ** PDWORD pcchFallbackLanguages
    ** PDWORD pAttributes


NotifyUILanguageChange
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** PCWSTR pcwstrNewLanguage
    ** PCWSTR pcwstrPreviousLanguage
    ** DWORD dwReserved
    ** PDWORD pdwStatusRtrn


GetStringTypeExA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LCID Locale
    ** DWORD dwInfoType
    ** LPCSTR lpSrcStr
    ** int cchSrc


GetStringTypeA
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LCID Locale
    ** DWORD dwInfoType
    ** LPCSTR lpSrcStr
    ** int cchSrc
    ** LPWORD lpCharType


FoldStringA
===========

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** DWORD dwMapFlags
    ** LPCSTR lpSrcStr
    ** int cchSrc
    ** LPSTR lpDestStr
    ** int cchDest


EnumSystemLocalesA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LOCALE_ENUMPROCA lpLocaleEnumProc
    ** DWORD dwFlags


EnumSystemLocalesW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LOCALE_ENUMPROCW lpLocaleEnumProc
    ** DWORD dwFlags


EnumSystemLanguageGroupsA
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LANGUAGEGROUP_ENUMPROCA lpLanguageGroupEnumProc
    ** DWORD dwFlags
    ** LONG_PTR lParam


EnumSystemLanguageGroupsW
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LANGUAGEGROUP_ENUMPROCW lpLanguageGroupEnumProc
    ** DWORD dwFlags
    ** LONG_PTR lParam


EnumLanguageGroupLocalesA
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LANGGROUPLOCALE_ENUMPROCA lpLangGroupLocaleEnumProc
    ** LGRPID LanguageGroup
    ** DWORD dwFlags
    ** LONG_PTR lParam


EnumLanguageGroupLocalesW
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LANGGROUPLOCALE_ENUMPROCW lpLangGroupLocaleEnumProc
    ** LGRPID LanguageGroup
    ** DWORD dwFlags
    ** LONG_PTR lParam


EnumUILanguagesA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UILANGUAGE_ENUMPROCA lpUILanguageEnumProc
    ** DWORD dwFlags
    ** LONG_PTR lParam


EnumUILanguagesW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UILANGUAGE_ENUMPROCW lpUILanguageEnumProc
    ** DWORD dwFlags
    ** LONG_PTR lParam


EnumSystemCodePagesA
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** CODEPAGE_ENUMPROCA lpCodePageEnumProc
    ** DWORD dwFlags


EnumSystemCodePagesW
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** CODEPAGE_ENUMPROCW lpCodePageEnumProc
    ** DWORD dwFlags


GetLocaleInfoEx
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpLocaleName
    ** LCTYPE LCType
    ** LPWSTR lpLCData
    ** int cchData


GetCalendarInfoEx
=================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCWSTR lpLocaleName
    ** CALID Calendar
    ** LPCWSTR lpReserved
    ** CALTYPE CalType
    ** LPWSTR lpCalData
    ** int cchData
    ** LPDWORD lpValue


GetDurationFormatEx
===================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCWSTR lpLocaleName
    ** DWORD dwFlags
    ** SYSTEMTIME *lpDuration
    ** ULONGLONG ullDuration
    ** LPCWSTR lpFormat
    ** LPWSTR lpDurationStr
    ** int cchDuration


GetNumberFormatEx
=================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCWSTR lpLocaleName
    ** DWORD dwFlags
    ** LPCWSTR lpValue
    ** NUMBERFMTW *lpFormat
    ** LPWSTR lpNumberStr
    ** int cchNumber


GetCurrencyFormatEx
===================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCWSTR lpLocaleName
    ** DWORD dwFlags
    ** LPCWSTR lpValue
    ** CURRENCYFMTW *lpFormat
    ** LPWSTR lpCurrencyStr
    ** int cchCurrency


GetUserDefaultLocaleName
========================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPWSTR lpLocaleName
    ** int cchLocaleName


GetSystemDefaultLocaleName
==========================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPWSTR lpLocaleName
    ** int cchLocaleName


GetNLSVersionEx
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** NLS_FUNCTION function
    ** LPCWSTR lpLocaleName
    ** LPNLSVERSIONINFOEX lpVersionInformation


IsValidNLSVersion
=================

Signature::

    * Library: 
    * Return value: DWORD

Parameters::

    ** NLS_FUNCTION function
    ** LPCWSTR lpLocaleName
    ** LPNLSVERSIONINFOEX lpVersionInformation


FindNLSStringEx
===============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCWSTR lpLocaleName
    ** DWORD dwFindNLSStringFlags
    ** LPCWSTR lpStringSource
    ** int cchSource
    ** LPCWSTR lpStringValue
    ** int cchValue
    ** LPINT pcchFound
    ** LPNLSVERSIONINFO lpVersionInformation
    ** LPVOID lpReserved
    ** LPARAM sortHandle


LCMapStringEx
=============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCWSTR lpLocaleName
    ** DWORD dwMapFlags
    ** LPCWSTR lpSrcStr
    ** int cchSrc
    ** LPWSTR lpDestStr
    ** int cchDest
    ** LPNLSVERSIONINFO lpVersionInformation
    ** LPVOID lpReserved
    ** LPARAM sortHandle


IsValidLocaleName
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpLocaleName


EnumCalendarInfoExEx
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** CALINFO_ENUMPROCEXEX pCalInfoEnumProcExEx
    ** LPCWSTR lpLocaleName
    ** CALID Calendar
    ** LPCWSTR lpReserved
    ** CALTYPE CalType
    ** LPARAM lParam


EnumDateFormatsExEx
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DATEFMT_ENUMPROCEXEX lpDateFmtEnumProcExEx
    ** LPCWSTR lpLocaleName
    ** DWORD dwFlags
    ** LPARAM lParam


EnumTimeFormatsEx
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** TIMEFMT_ENUMPROCEX lpTimeFmtEnumProcEx
    ** LPCWSTR lpLocaleName
    ** DWORD dwFlags
    ** LPARAM lParam


EnumSystemLocalesEx
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LOCALE_ENUMPROCEX lpLocaleEnumProcEx
    ** DWORD dwFlags
    ** LPARAM lParam
    ** LPVOID lpReserved


ResolveLocaleName
=================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LPCWSTR lpNameToResolve
    ** LPWSTR lpLocaleName
    ** int cchLocaleName


Wow64DisableWow64FsRedirection
==============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PVOID *OldValue


Wow64RevertWow64FsRedirection
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PVOID OlValue


IsWow64Process
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PBOOL Wow64Process


