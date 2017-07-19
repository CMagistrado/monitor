Signature::

    * Calling convention: WINAPI
    * Category: none


AddDllDirectory
===============

Signature::

    * Library: kernel32
    * Return value: DLL_DIRECTORY_COOKIE

Parameters::

    ** PCWSTR NewDirectory


DisableThreadLibraryCalls
=========================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HMODULE hLibModule


FreeLibrary
===========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HMODULE hLibModule


FreeLibraryAndExitThread
========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** HMODULE hLibModule
    ** DWORD dwExitCode


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


GetModuleFileNameA
==================

Signature::

    * Library: rtmpal
    * Return value: DWORD

Parameters::

    ** HMODULE hModule
    ** LPSTR lpFilename
    ** DWORD nSize


GetModuleFileNameW
==================

Signature::

    * Library: rtmpal
    * Return value: DWORD

Parameters::

    ** HMODULE hModule
    ** LPWSTR lpFilename
    ** DWORD nSize


GetModuleFileNameExA
====================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess
    ** HMODULE hModule
    ** LPSTR lpFilename
    ** DWORD nSize


GetModuleFileNameExW
====================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess
    ** HMODULE hModule
    ** LPWSTR lpFilename
    ** DWORD nSize


GetProcAddress
==============

Signature::

    * Library: rtmpal
    * Return value: FARPROC

Parameters::

    ** HMODULE hModule
    ** LPCSTR lpProcName


LoadLibraryA
============

Signature::

    * Library: rtmpal
    * Return value: HMODULE

Parameters::

    ** LPCSTR lpLibFileName


LoadLibraryW
============

Signature::

    * Library: rtmpal
    * Return value: HMODULE

Parameters::

    ** LPCWSTR lpLibFileName


LoadLibraryExA
==============

Signature::

    * Library: rtmpal
    * Return value: HMODULE

Parameters::

    ** LPCSTR lpLibFileName
    ** HANDLE hFile
    ** DWORD dwFlags


LoadLibraryExW
==============

Signature::

    * Library: rtmpal
    * Return value: HMODULE

Parameters::

    ** LPCWSTR lpLibFileName
    ** HANDLE hFile
    ** DWORD dwFlags


LoadPackagedLibrary
===================

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    ** LPCWSTR lpwLibFileName
    ** DWORD Reserved


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


AddUsersToEncryptedFile
=======================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** PENCRYPTION_CERTIFICATE_LIST pEncryptionCertificates


AreFileApisANSI
===============

Signature::

    * Library: kernel32
    * Return value: BOOL


CancelIo
========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile


CancelIoEx
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPOVERLAPPED lpOverlapped


CancelSynchronousIo
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread


CheckNameLegalDOS8Dot3A
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpName
    ** LPSTR lpOemName
    ** DWORD OemNameSize
    ** PBOOL pbNameContainsSpaces
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
    ** PBOOL pbNameContainsSpaces
    ** PBOOL pbNameLegal


CloseEncryptedFileRaw
=====================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    ** PVOID pvContext


CopyFileA
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpExistingFileName
    ** LPCSTR lpNewFileName
    ** BOOL bFailIfExists

Pre::

    wchar_t *newfilepath = get_unicode_buffer();

    // From https://stackoverflow.com/questions/22706166/how-to-convert-lpcstr-to-wchar#22706856
    int wchars_num =  MultiByteToWideChar( CP_UTF8 , 0 , lpNewFileName  , -1, NULL , 0 );
    WCHAR wstr_n[wchars_num];
    MultiByteToWideChar( CP_UTF8 , 0 , lpNewFileName  , -1, wstr_n , wchars_num );

    if(lpNewFileName != NULL) {
        path_get_full_pathW(wstr_n, newfilepath);
    }

Post::

    if(ret != FALSE) {
        pipe("FILE_NEW:%Z", newfilepath);
    }

    free_unicode_buffer(newfilepath);


CopyFileW
=========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpExistingFileName
    ** LPCWSTR lpNewFileName
    ** BOOL bFailIfExists

Pre::

    wchar_t *newfilepath = get_unicode_buffer();
    if(lpNewFileName != NULL) {
        path_get_full_pathW(lpNewFileName, newfilepath);
    }

Post::

    if(ret != FALSE) {
        pipe("FILE_NEW:%Z", newfilepath);
    }

    free_unicode_buffer(newfilepath);


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

Pre::

    wchar_t *newfilepath = get_unicode_buffer();

    // From https://stackoverflow.com/questions/22706166/how-to-convert-lpcstr-to-wchar#22706856
    int wchars_num =  MultiByteToWideChar( CP_UTF8 , 0 , lpNewFileName  , -1, NULL , 0 );
    WCHAR wstr_n[wchars_num];
    MultiByteToWideChar( CP_UTF8 , 0 , lpNewFileName  , -1, wstr_n , wchars_num );

    if(lpNewFileName != NULL) {
        path_get_full_pathW(wstr_n, newfilepath);
    }

Post::

    if(ret != FALSE) {
        pipe("FILE_NEW:%Z", newfilepath);
    }

    free_unicode_buffer(newfilepath);


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

Pre::

    wchar_t *newfilepath = get_unicode_buffer();
    if(lpNewFileName != NULL) {
        path_get_full_pathW(lpNewFileName, newfilepath);
    }

Post::

    if(ret != FALSE) {
        pipe("FILE_NEW:%Z", newfilepath);
    }

    free_unicode_buffer(newfilepath);


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

Pre::

    wchar_t *newfilepath = get_unicode_buffer();

    // From https://stackoverflow.com/questions/22706166/how-to-convert-lpcstr-to-wchar#22706856
    int wchars_num =  MultiByteToWideChar( CP_UTF8 , 0 , lpNewFileName  , -1, NULL , 0 );
    WCHAR wstr_n[wchars_num];
    MultiByteToWideChar( CP_UTF8 , 0 , lpNewFileName  , -1, wstr_n , wchars_num );

    if(lpNewFileName != NULL) {
        path_get_full_pathW(wstr_n, newfilepath);
    }

Post::

    if(ret != FALSE) {
        pipe("FILE_NEW:%Z", newfilepath);
    }

    free_unicode_buffer(newfilepath);


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

Pre::

    wchar_t *newfilepath = get_unicode_buffer();
    if(lpNewFileName != NULL) {
        path_get_full_pathW(lpNewFileName, newfilepath);
    }

Post::

    if(ret != FALSE) {
        pipe("FILE_NEW:%Z", newfilepath);
    }

    free_unicode_buffer(newfilepath);


CreateDirectoryA
================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** LPCSTR lpPathName
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateDirectoryW
================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpPathName
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes


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


CreateFileA
===========

Signature::

    * Library: rtmpal
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

    * Library: rtmpal
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD dwDesiredAccess
    ** DWORD dwShareMode
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** DWORD dwCreationDisposition
    ** DWORD dwFlagsAndAttributes
    ** HANDLE hTemplateFile


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


DecryptFileA
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** DWORD dwReserved


DecryptFileW
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD dwReserved


DeleteFileA
===========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName

Pre::

    wchar_t *filepath = get_unicode_buffer();

    // From https://stackoverflow.com/questions/22706166/how-to-convert-lpcstr-to-wchar#22706856
    int wchars_num =  MultiByteToWideChar( CP_UTF8 , 0 , lpFileName  , -1, NULL , 0 );
    WCHAR wstr[wchars_num];
    MultiByteToWideChar( CP_UTF8 , 0 , lpFileName  , -1, wstr , wchars_num );

    path_get_full_pathW(wstr, filepath);
    pipe("FILE_DEL:%Z", filepath);

Post::

    free_unicode_buffer(filepath);


DeleteFileW
===========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpFileName, filepath);
    pipe("FILE_DEL:%Z", filepath);

Post::

    free_unicode_buffer(filepath);


DeleteFileTransactedA
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** HANDLE hTransaction

Pre::

    wchar_t *filepath = get_unicode_buffer();

    // From https://stackoverflow.com/questions/22706166/how-to-convert-lpcstr-to-wchar#22706856
    int wchars_num =  MultiByteToWideChar( CP_UTF8 , 0 , lpFileName  , -1, NULL , 0 );
    WCHAR wstr[wchars_num];
    MultiByteToWideChar( CP_UTF8 , 0 , lpFileName  , -1, wstr , wchars_num );

    path_get_full_pathW(wstr, filepath);
    pipe("FILE_DEL:%Z", filepath);

Post::

    free_unicode_buffer(filepath);


DeleteFileTransactedW
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** HANDLE hTransaction

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpFileName, filepath);
    pipe("FILE_DEL:%Z", filepath);

Post::

    free_unicode_buffer(filepath);


DuplicateEncryptionInfoFile
===========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** LPCWSTR SrcFileName
    ** LPCWSTR DstFileName
    ** DWORD dwCreationDistribution
    ** DWORD dwAttributes
    ** const LPSECURITY_ATTRIBUTES lpSecurityAttributes


EncryptFileA
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName


EncryptFileW
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName


EncryptionDisable
=================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCWSTR DirPath
    ** BOOL Disable


FileEncryptionStatusA
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** LPDWORD lpStatus


FileEncryptionStatusW
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** LPDWORD lpStatus


FindClose
=========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hFindFile


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

    * Library: rtmpal
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

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hFindFile
    ** LPWIN32_FIND_DATAW lpFindFileData


FindNextFileNameW
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindStream
    ** LPDWORD StringLength
    ** PWSTR LinkName


FindNextStreamW
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindStream
    ** LPVOID lpFindStreamData


FlushFileBuffers
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile


FreeEncryptionCertificateHashList
=================================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    ** PENCRYPTION_CERTIFICATE_HASH_LIST pUsers


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

    * Library: rtmpal
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

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** GET_FILEEX_INFO_LEVELS fInfoLevelId
    ** LPVOID lpFileInformation


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


GetFileInformationByHandle
==========================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPBY_HANDLE_FILE_INFORMATION lpFileInformation


GetFileInformationByHandleEx
============================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** FILE_INFO_BY_HANDLE_CLASS FileInformationClass
    ** LPVOID lpFileInformation
    ** DWORD dwBufferSize


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

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** PLARGE_INTEGER lpFileSize


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


GetShortPathNameA
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpszLongPath
    ** LPSTR lpszShortPath
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


GetTempPathA
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPSTR lpBuffer


GetTempPathW
============

Signature::

    * Library: rtmpal
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPWSTR lpBuffer


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


MoveFileA
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpExistingFileName
    ** LPCSTR lpNewFileName

Pre::

    wchar_t *oldfilepath = get_unicode_buffer();

    // From https://stackoverflow.com/questions/22706166/how-to-convert-lpcstr-to-wchar#22706856
    int wchars_num =  MultiByteToWideChar( CP_UTF8 , 0 , lpExistingFileName  , -1, NULL , 0 );
    WCHAR wstr_e[wchars_num];
    MultiByteToWideChar( CP_UTF8 , 0 , lpExistingFileName  , -1, wstr_e , wchars_num );

    path_get_full_pathW(wstr_e, oldfilepath);

    wchar_t *newfilepath = get_unicode_buffer();

    // From https://stackoverflow.com/questions/22706166/how-to-convert-lpcstr-to-wchar#22706856
    wchars_num =  MultiByteToWideChar( CP_UTF8 , 0 , lpNewFileName  , -1, NULL , 0 );
    WCHAR wstr_n[wchars_num];
    MultiByteToWideChar( CP_UTF8 , 0 , lpNewFileName  , -1, wstr_n , wchars_num );

    if(lpNewFileName != NULL) {
        path_get_full_pathW(wstr_n, newfilepath);
    }

Post::

    if(ret != FALSE) {
        if(lpNewFileName == NULL) {
            pipe("FILE_DEL:%Z", oldfilepath);
        }
        else {
            pipe("FILE_MOVE:%Z::%Z", oldfilepath, newfilepath);
        }
    }

    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);


MoveFileW
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpExistingFileName
    ** LPCWSTR lpNewFileName

Pre::

    wchar_t *oldfilepath = get_unicode_buffer();
    path_get_full_pathW(lpExistingFileName, oldfilepath);

    wchar_t *newfilepath = get_unicode_buffer();
    if(lpNewFileName != NULL) {
        path_get_full_pathW(lpNewFileName, newfilepath);
    }

Post::

    if(ret != FALSE) {
        if(lpNewFileName == NULL) {
            pipe("FILE_DEL:%Z", oldfilepath);
        }
        else {
            pipe("FILE_MOVE:%Z::%Z", oldfilepath, newfilepath);
        }
    }

    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);


MoveFileExA
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpExistingFileName
    ** LPCSTR lpNewFileName
    ** DWORD dwFlags

Pre::

    wchar_t *oldfilepath = get_unicode_buffer();

    // From https://stackoverflow.com/questions/22706166/how-to-convert-lpcstr-to-wchar#22706856
    int wchars_num =  MultiByteToWideChar( CP_UTF8 , 0 , lpExistingFileName  , -1, NULL , 0 );
    WCHAR wstr_e[wchars_num];
    MultiByteToWideChar( CP_UTF8 , 0 , lpExistingFileName  , -1, wstr_e , wchars_num );

    path_get_full_pathW(wstr_e, oldfilepath);

    wchar_t *newfilepath = get_unicode_buffer();

    // From https://stackoverflow.com/questions/22706166/how-to-convert-lpcstr-to-wchar#22706856
    wchars_num =  MultiByteToWideChar( CP_UTF8 , 0 , lpNewFileName  , -1, NULL , 0 );
    WCHAR wstr_n[wchars_num];
    MultiByteToWideChar( CP_UTF8 , 0 , lpNewFileName  , -1, wstr_n , wchars_num );

    if(lpNewFileName != NULL) {
        path_get_full_pathW(wstr_n, newfilepath);
    }

Post::

    if(ret != FALSE) {
        if(lpNewFileName == NULL) {
            pipe("FILE_DEL:%Z", oldfilepath);
        }
        else {
            pipe("FILE_MOVE:%Z::%Z", oldfilepath, newfilepath);
        }
    }

    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);


MoveFileExW
===========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpExistingFileName
    ** LPCWSTR lpNewFileName
    ** DWORD dwFlags

Pre::

    wchar_t *oldfilepath = get_unicode_buffer();
    path_get_full_pathW(lpExistingFileName, oldfilepath);

    wchar_t *newfilepath = get_unicode_buffer();
    if(lpNewFileName != NULL) {
        path_get_full_pathW(lpNewFileName, newfilepath);
    }

Post::

    if(ret != FALSE) {
        if(lpNewFileName == NULL) {
            pipe("FILE_DEL:%Z", oldfilepath);
        }
        else {
            pipe("FILE_MOVE:%Z::%Z", oldfilepath, newfilepath);
        }
    }

    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);


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

Pre::

    wchar_t *oldfilepath = get_unicode_buffer();

    // From https://stackoverflow.com/questions/22706166/how-to-convert-lpcstr-to-wchar#22706856
    int wchars_num =  MultiByteToWideChar( CP_UTF8 , 0 , lpExistingFileName  , -1, NULL , 0 );
    WCHAR wstr_e[wchars_num];
    MultiByteToWideChar( CP_UTF8 , 0 , lpExistingFileName  , -1, wstr_e , wchars_num );

    path_get_full_pathW(wstr_e, oldfilepath);

    wchar_t *newfilepath = get_unicode_buffer();

    // From https://stackoverflow.com/questions/22706166/how-to-convert-lpcstr-to-wchar#22706856
    wchars_num =  MultiByteToWideChar( CP_UTF8 , 0 , lpNewFileName  , -1, NULL , 0 );
    WCHAR wstr_n[wchars_num];
    MultiByteToWideChar( CP_UTF8 , 0 , lpNewFileName  , -1, wstr_n , wchars_num );

    if(lpNewFileName != NULL) {
        path_get_full_pathW(wstr_n, newfilepath);
    }

Post::

    if(ret != FALSE) {
        if(lpNewFileName == NULL) {
            pipe("FILE_DEL:%Z", oldfilepath);
        }
        else {
            pipe("FILE_MOVE:%Z::%Z", oldfilepath, newfilepath);
        }
    }

    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);


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

Pre::

    wchar_t *oldfilepath = get_unicode_buffer();
    path_get_full_pathW(lpExistingFileName, oldfilepath);

    wchar_t *newfilepath = get_unicode_buffer();
    if(lpNewFileName != NULL) {
        path_get_full_pathW(lpNewFileName, newfilepath);
    }

Post::

    if(ret != FALSE) {
        if(lpNewFileName == NULL) {
            pipe("FILE_DEL:%Z", oldfilepath);
        }
        else {
            pipe("FILE_MOVE:%Z::%Z", oldfilepath, newfilepath);
        }
    }

    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);


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

Pre::

    wchar_t *oldfilepath = get_unicode_buffer();

    // From https://stackoverflow.com/questions/22706166/how-to-convert-lpcstr-to-wchar#22706856
    int wchars_num =  MultiByteToWideChar( CP_UTF8 , 0 , lpExistingFileName  , -1, NULL , 0 );
    WCHAR wstr_e[wchars_num];
    MultiByteToWideChar( CP_UTF8 , 0 , lpExistingFileName  , -1, wstr_e , wchars_num );

    path_get_full_pathW(wstr_e, oldfilepath);

    wchar_t *newfilepath = get_unicode_buffer();

    // From https://stackoverflow.com/questions/22706166/how-to-convert-lpcstr-to-wchar#22706856
    wchars_num =  MultiByteToWideChar( CP_UTF8 , 0 , lpNewFileName  , -1, NULL , 0 );
    WCHAR wstr_n[wchars_num];
    MultiByteToWideChar( CP_UTF8 , 0 , lpNewFileName  , -1, wstr_n , wchars_num );

    if(lpNewFileName != NULL) {
        path_get_full_pathW(wstr_n, newfilepath);
    }

Post::

    if(ret != FALSE) {
        if(lpNewFileName == NULL) {
            pipe("FILE_DEL:%Z", oldfilepath);
        }
        else {
            pipe("FILE_MOVE:%Z::%Z", oldfilepath, newfilepath);
        }
    }

    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);


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

Pre::

    wchar_t *oldfilepath = get_unicode_buffer();
    path_get_full_pathW(lpExistingFileName, oldfilepath);

    wchar_t *newfilepath = get_unicode_buffer();
    if(lpNewFileName != NULL) {
        path_get_full_pathW(lpNewFileName, newfilepath);
    }

Post::

    if(ret != FALSE) {
        if(lpNewFileName == NULL) {
            pipe("FILE_DEL:%Z", oldfilepath);
        }
        else {
            pipe("FILE_MOVE:%Z::%Z", oldfilepath, newfilepath);
        }
    }

    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);


OpenEncryptedFileRawA
=====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpFileName
    ** ULONG ulFlags
    ** PVOID *pvContext


OpenEncryptedFileRawW
=====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** ULONG ulFlags
    ** PVOID *pvContext


OpenFile
========

Signature::

    * Library: kernel32
    * Return value: HFILE

Parameters::

    ** LPCSTR lpFileName
    ** LPOFSTRUCT lpReOpenBuff
    ** UINT uStyle


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


QueryRecoveryAgentsOnEncryptedFile
==================================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** PENCRYPTION_CERTIFICATE_HASH_LIST *pRecoveryAgents


QueryUsersOnEncryptedFile
=========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** PENCRYPTION_CERTIFICATE_HASH_LIST *pUsers


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


ReadEncryptedFileRaw
====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** PFE_EXPORT_FUNC pfExportCallback
    ** PVOID pvCallbackContext
    ** PVOID pvContext


ReadFile
========

Signature::

    * Library: rtmpal
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

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpPathName


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


RemoveUsersFromEncryptedFile
============================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** PENCRYPTION_CERTIFICATE_HASH_LIST pHashes


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


SetEndOfFile
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile


SetFileApisToANSI
=================

Signature::

    * Library: kernel32
    * Return value: void


SetFileApisToOEM
================

Signature::

    * Library: kernel32
    * Return value: void


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

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD dwFileAttributes


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


SetFileCompletionNotificationModes
==================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE FileHandle
    ** UCHAR Flags


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


SetFileIoOverlappedRange
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE FileHandle
    ** PUCHAR OverlappedRangeStart
    ** ULONG Length


SetFilePointer
==============

Signature::

    * Library: rtmpal
    * Return value: DWORD

Parameters::

    ** HANDLE hFile
    ** LONG lDistanceToMove
    ** PLONG lpDistanceToMoveHigh
    ** DWORD dwMoveMethod


SetFilePointerEx
================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LARGE_INTEGER liDistanceToMove
    ** PLARGE_INTEGER lpNewFilePointer
    ** DWORD dwMoveMethod


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


SetFileValidData
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LONGLONG ValidDataLength


SetSearchPathMode
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD Flags


SetUserFileEncryptionKey
========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** PENCRYPTION_CERTIFICATE pEncryptionCertificate


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


Wow64DisableWow64FsRedirection
==============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PVOID *OldValue


Wow64EnableWow64FsRedirection
=============================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    ** BOOLEAN Wow64FsEnableRedirection


Wow64RevertWow64FsRedirection
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PVOID OlValue


WriteEncryptedFileRaw
=====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** PFE_IMPORT_FUNC pfImportCallback
    ** PVOID pvCallbackContext
    ** PVOID pvContext


WriteFile
=========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPCVOID lpBuffer
    ** DWORD nNumberOfBytesToWrite
    ** LPDWORD lpNumberOfBytesWritten
    ** LPOVERLAPPED lpOverlapped

Post::

    wchar_t *filepath = get_unicode_buffer();

    if(NT_SUCCESS(ret) != FALSE &&
            path_get_full_path_handle(hFile, filepath) != 0) {
        pipe("FILE_NEW:%Z", filepath);
    }

    free_unicode_buffer(filepath);


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

Post::

    wchar_t *filepath = get_unicode_buffer();

    if(NT_SUCCESS(ret) != FALSE &&
            path_get_full_path_handle(hFile, filepath) != 0) {
        pipe("FILE_NEW:%Z", filepath);
    }

    free_unicode_buffer(filepath);


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

Post::

    wchar_t *filepath = get_unicode_buffer();

    if(NT_SUCCESS(ret) != FALSE &&
            path_get_full_path_handle(hFile, filepath) != 0) {
        pipe("FILE_NEW:%Z", filepath);
    }

    free_unicode_buffer(filepath);


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

Pre::

    wchar_t *oldfilepath = get_unicode_buffer();

    // From https://stackoverflow.com/questions/22706166/how-to-convert-lpcstr-to-wchar#22706856
    int wchars_num =  MultiByteToWideChar( CP_UTF8 , 0 , lpReplacementFileName  , -1, NULL , 0 );
    WCHAR wstr_e[wchars_num];
    MultiByteToWideChar( CP_UTF8 , 0 , lpReplacementFileName  , -1, wstr_e , wchars_num );

    path_get_full_pathW(wstr_e, oldfilepath);


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

Pre::

    wchar_t *oldfilepath = get_unicode_buffer();
    path_get_full_pathW(lpReplacementFileName, oldfilepath);

    wchar_t *newfilepath = get_unicode_buffer();
    if(lpReplacedFileName != NULL) {
        path_get_full_pathW(lpReplacedFileName, newfilepath);
    }

    wchar_t *backupfilepath = get_unicode_buffer();
    if(lpBackupFileName != NULL) {
        path_get_full_pathW(lpBackupFileName, backupfilepath);
    }

Post::

    if(ret != FALSE) {
        pipe("FILE_DEL:%Z", newfilepath);

        if (lpBackupFileName != NULL) {
            pipe("FILE_NEW:%Z", backupfilepath);
        }

        pipe("FILE_MOVE:%Z::%Z", oldfilepath, newfilepath);
    }

    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);
    free_unicode_buffer(backupfilepath);


ChangeServiceConfigA
====================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwServiceType
    ** DWORD dwStartType
    ** DWORD dwErrorControl
    ** LPCSTR lpBinaryPathName
    ** LPCSTR lpLoadOrderGroup
    ** LPDWORD lpdwTagId
    ** LPCSTR lpDependencies
    ** LPCSTR lpServiceStartName
    ** LPCSTR lpPassword
    ** LPCSTR lpDisplayName


ChangeServiceConfigW
====================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwServiceType
    ** DWORD dwStartType
    ** DWORD dwErrorControl
    ** LPCWSTR lpBinaryPathName
    ** LPCWSTR lpLoadOrderGroup
    ** LPDWORD lpdwTagId
    ** LPCWSTR lpDependencies
    ** LPCWSTR lpServiceStartName
    ** LPCWSTR lpPassword
    ** LPCWSTR lpDisplayName


ChangeServiceConfig2A
=====================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwInfoLevel
    ** LPVOID lpInfo


ChangeServiceConfig2W
=====================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwInfoLevel
    ** LPVOID lpInfo


CloseServiceHandle
==================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hSCObject


ControlService
==============

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwControl
    ** LPSERVICE_STATUS lpServiceStatus


ControlServiceExA
=================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwControl
    ** DWORD dwInfoLevel
    ** PVOID pControlParams


ControlServiceExW
=================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwControl
    ** DWORD dwInfoLevel
    ** PVOID pControlParams


CreateServiceA
==============

Signature::

    * Library: sechost
    * Return value: SC_HANDLE

Parameters::

    ** SC_HANDLE hSCManager
    ** LPCSTR lpServiceName
    ** LPCSTR lpDisplayName
    ** DWORD dwDesiredAccess
    ** DWORD dwServiceType
    ** DWORD dwStartType
    ** DWORD dwErrorControl
    ** LPCSTR lpBinaryPathName
    ** LPCSTR lpLoadOrderGroup
    ** LPDWORD lpdwTagId
    ** LPCSTR lpDependencies
    ** LPCSTR lpServiceStartName
    ** LPCSTR lpPassword


CreateServiceW
==============

Signature::

    * Library: sechost
    * Return value: SC_HANDLE

Parameters::

    ** SC_HANDLE hSCManager
    ** LPCWSTR lpServiceName
    ** LPCWSTR lpDisplayName
    ** DWORD dwDesiredAccess
    ** DWORD dwServiceType
    ** DWORD dwStartType
    ** DWORD dwErrorControl
    ** LPCWSTR lpBinaryPathName
    ** LPCWSTR lpLoadOrderGroup
    ** LPDWORD lpdwTagId
    ** LPCWSTR lpDependencies
    ** LPCWSTR lpServiceStartName
    ** LPCWSTR lpPassword


DeleteService
=============

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService


EnumDependentServicesA
======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwServiceState
    ** LPENUM_SERVICE_STATUSA lpServices
    ** DWORD cbBufSize
    ** LPDWORD pcbBytesNeeded
    ** LPDWORD lpServicesReturned


EnumDependentServicesW
======================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwServiceState
    ** LPENUM_SERVICE_STATUSW lpServices
    ** DWORD cbBufSize
    ** LPDWORD pcbBytesNeeded
    ** LPDWORD lpServicesReturned


EnumServicesStatusExA
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hSCManager
    ** SC_ENUM_TYPE InfoLevel
    ** DWORD dwServiceType
    ** DWORD dwServiceState
    ** LPBYTE lpServices
    ** DWORD cbBufSize
    ** LPDWORD pcbBytesNeeded
    ** LPDWORD lpServicesReturned
    ** LPDWORD lpResumeHandle
    ** LPCSTR pszGroupName


EnumServicesStatusExW
=====================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hSCManager
    ** SC_ENUM_TYPE InfoLevel
    ** DWORD dwServiceType
    ** DWORD dwServiceState
    ** LPBYTE lpServices
    ** DWORD cbBufSize
    ** LPDWORD pcbBytesNeeded
    ** LPDWORD lpServicesReturned
    ** LPDWORD lpResumeHandle
    ** LPCWSTR pszGroupName


GetServiceDisplayNameA
======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hSCManager
    ** LPCSTR lpServiceName
    ** LPSTR lpDisplayName
    ** LPDWORD lpcchBuffer


GetServiceDisplayNameW
======================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hSCManager
    ** LPCWSTR lpServiceName
    ** LPWSTR lpDisplayName
    ** LPDWORD lpcchBuffer


GetServiceKeyNameA
==================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hSCManager
    ** LPCSTR lpDisplayName
    ** LPSTR lpServiceName
    ** LPDWORD lpcchBuffer


GetServiceKeyNameW
==================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hSCManager
    ** LPCWSTR lpDisplayName
    ** LPWSTR lpServiceName
    ** LPDWORD lpcchBuffer


NotifyBootConfigStatus
======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** BOOL BootAcceptable


NotifyServiceStatusChangeA
==========================

Signature::

    * Library: sechost
    * Return value: DWORD

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwNotifyMask
    ** PSERVICE_NOTIFYA pNotifyBuffer


NotifyServiceStatusChangeW
==========================

Signature::

    * Library: sechost
    * Return value: DWORD

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwNotifyMask
    ** PSERVICE_NOTIFYW pNotifyBuffer


OpenServiceA
============

Signature::

    * Library: sechost
    * Return value: SC_HANDLE

Parameters::

    ** SC_HANDLE hSCManager
    ** LPCSTR lpServiceName
    ** DWORD dwDesiredAccess


OpenServiceW
============

Signature::

    * Library: sechost
    * Return value: SC_HANDLE

Parameters::

    ** SC_HANDLE hSCManager
    ** LPCWSTR lpServiceName
    ** DWORD dwDesiredAccess


QueryServiceConfigA
===================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** LPQUERY_SERVICE_CONFIGA lpServiceConfig
    ** DWORD cbBufSize
    ** LPDWORD pcbBytesNeeded


QueryServiceConfigW
===================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** LPQUERY_SERVICE_CONFIGW lpServiceConfig
    ** DWORD cbBufSize
    ** LPDWORD pcbBytesNeeded


QueryServiceConfig2A
====================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwInfoLevel
    ** LPBYTE lpBuffer
    ** DWORD cbBufSize
    ** LPDWORD pcbBytesNeeded


QueryServiceConfig2W
====================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwInfoLevel
    ** LPBYTE lpBuffer
    ** DWORD cbBufSize
    ** LPDWORD pcbBytesNeeded


QueryServiceDynamicInformation
==============================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SERVICE_STATUS_HANDLE hServiceStatus
    ** DWORD dwInfoLevel
    ** PVOID *ppDynamicInfo


QueryServiceObjectSecurity
==========================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** SECURITY_INFORMATION dwSecurityInformation
    ** PSECURITY_DESCRIPTOR lpSecurityDescriptor
    ** DWORD cbBufSize
    ** LPDWORD pcbBytesNeeded


QueryServiceStatusEx
====================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** SC_STATUS_TYPE InfoLevel
    ** LPBYTE lpBuffer
    ** DWORD cbBufSize
    ** LPDWORD pcbBytesNeeded


SetServiceObjectSecurity
========================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** SECURITY_INFORMATION dwSecurityInformation
    ** PSECURITY_DESCRIPTOR lpSecurityDescriptor


SetServiceStatus
================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SERVICE_STATUS_HANDLE hServiceStatus
    ** LPSERVICE_STATUS lpServiceStatus


StartServiceA
=============

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwNumServiceArgs
    ** LPCSTR *lpServiceArgVectors


StartServiceW
=============

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwNumServiceArgs
    ** LPCWSTR *lpServiceArgVectors


StartServiceCtrlDispatcherA
===========================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** const SERVICE_TABLE_ENTRYA *lpServiceStartTable


StartServiceCtrlDispatcherW
===========================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** const SERVICE_TABLE_ENTRYW *lpServiceStartTable


CeipIsOptedIn
=============

Signature::

    * Library: kernel32
    * Return value: BOOL


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


EnumSystemFirmwareTables
========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** DWORD FirmwareTableProviderSignature
    ** PVOID pFirmwareTableEnumBuffer
    ** DWORD BufferSize


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

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** LPWSTR lpBuffer
    ** LPDWORD nSize


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


GetCurrentHwProfileA
====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPHW_PROFILE_INFOA lpHwProfileInfo


GetCurrentHwProfileW
====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPHW_PROFILE_INFOW lpHwProfileInfo


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


GetFirmwareEnvironmentVariableExA
=================================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpName
    ** LPCSTR lpGuid
    ** PVOID pBuffer
    ** DWORD nSize
    ** PDWORD pdwAttribubutes


GetFirmwareEnvironmentVariableExW
=================================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpName
    ** LPCWSTR lpGuid
    ** PVOID pBuffer
    ** DWORD nSize
    ** PDWORD pdwAttribubutes


GetFirmwareType
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PFIRMWARE_TYPE FirmwareType


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


GetSystemInfo
=============

Signature::

    * Library: rtmpal
    * Return value: void

Parameters::

    ** LPSYSTEM_INFO lpSystemInfo


GetSystemRegistryQuota
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PDWORD pdwQuotaAllowed
    ** PDWORD pdwQuotaUsed


GetUserNameA
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPSTR lpBuffer
    ** LPDWORD pcbBuffer


GetUserNameW
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPWSTR lpBuffer
    ** LPDWORD pcbBuffer


GetVersion
==========

Signature::

    * Library: kernel32
    * Return value: DWORD


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

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** LPOSVERSIONINFOW lpVersionInformation


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


IsNativeVhdBoot
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PBOOL NativeVhdBoot


IsProcessorFeaturePresent
=========================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** DWORD ProcessorFeature


QueryPerformanceCounter
=======================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** LARGE_INTEGER *lpPerformanceCount


QueryPerformanceFrequency
=========================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** LARGE_INTEGER *lpFrequency


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


SetComputerNameExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** COMPUTER_NAME_FORMAT NameType
    ** LPCWSTR lpBuffer


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


SetFirmwareEnvironmentVariableExA
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpName
    ** LPCSTR lpGuid
    ** PVOID pValue
    ** DWORD nSize
    ** DWORD dwAttributes


SetFirmwareEnvironmentVariableExW
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpName
    ** LPCWSTR lpGuid
    ** PVOID pValue
    ** DWORD nSize
    ** DWORD dwAttributes


VerSetConditionMask
===================

Signature::

    * Library: rtmpal
    * Return value: ULONGLONG

Parameters::

    ** ULONGLONG ConditionMask
    ** ULONG TypeMask
    ** UCHAR Condition


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


CloseHandle
===========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hObject


DuplicateHandle
===============

Signature::

    * Library: rtmpal
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


RegCloseKey
===========

Signature::

    * Library: rtmpal
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey


RegConnectRegistryA
===================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** LPCSTR lpMachineName
    ** HKEY hKey
    ** PHKEY phkResult


RegConnectRegistryW
===================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** LPCWSTR lpMachineName
    ** HKEY hKey
    ** PHKEY phkResult


RegCopyTreeA
============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKeySrc
    ** LPCSTR lpSubKey
    ** HKEY hKeyDest


RegCopyTreeW
============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKeySrc
    ** LPCWSTR lpSubKey
    ** HKEY hKeyDest


RegCreateKeyExA
===============

Signature::

    * Library: rtmpal
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** DWORD Reserved
    ** LPSTR lpClass
    ** DWORD dwOptions
    ** REGSAM samDesired
    ** const LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** PHKEY phkResult
    ** LPDWORD lpdwDisposition


RegCreateKeyExW
===============

Signature::

    * Library: rtmpal
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** DWORD Reserved
    ** LPWSTR lpClass
    ** DWORD dwOptions
    ** REGSAM samDesired
    ** const LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** PHKEY phkResult
    ** LPDWORD lpdwDisposition


RegCreateKeyTransactedA
=======================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** DWORD Reserved
    ** LPSTR lpClass
    ** DWORD dwOptions
    ** REGSAM samDesired
    ** const LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** PHKEY phkResult
    ** LPDWORD lpdwDisposition
    ** HANDLE hTransaction
    ** PVOID pExtendedParemeter


RegCreateKeyTransactedW
=======================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** DWORD Reserved
    ** LPWSTR lpClass
    ** DWORD dwOptions
    ** REGSAM samDesired
    ** const LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** PHKEY phkResult
    ** LPDWORD lpdwDisposition
    ** HANDLE hTransaction
    ** PVOID pExtendedParemeter


RegDeleteKeyA
=============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey


RegDeleteKeyW
=============

Signature::

    * Library: rtmpal
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey


RegDeleteKeyExA
===============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** REGSAM samDesired
    ** DWORD Reserved


RegDeleteKeyExW
===============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** REGSAM samDesired
    ** DWORD Reserved


RegDeleteKeyTransactedA
=======================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** REGSAM samDesired
    ** DWORD Reserved
    ** HANDLE hTransaction
    ** PVOID pExtendedParameter


RegDeleteKeyTransactedW
=======================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** REGSAM samDesired
    ** DWORD Reserved
    ** HANDLE hTransaction
    ** PVOID pExtendedParameter


RegDeleteKeyValueA
==================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** LPCSTR lpValueName


RegDeleteKeyValueW
==================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** LPCWSTR lpValueName


RegDeleteTreeA
==============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey


RegDeleteTreeW
==============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey


RegDeleteValueA
===============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpValueName


RegDeleteValueW
===============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpValueName


RegDisablePredefinedCache
=========================

Signature::

    * Library: advapi32
    * Return value: LSTATUS


RegDisablePredefinedCacheEx
===========================

Signature::

    * Library: kernel32
    * Return value: LSTATUS


RegDisableReflectionKey
=======================

Signature::

    * Library: advapi32
    * Return value: LONG

Parameters::

    ** HKEY hBase


RegEnableReflectionKey
======================

Signature::

    * Library: advapi32
    * Return value: LONG

Parameters::

    ** HKEY hBase


RegEnumValueA
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** DWORD dwIndex
    ** LPSTR lpValueName
    ** LPDWORD lpcchValueName
    ** LPDWORD lpReserved
    ** LPDWORD lpType
    ** LPBYTE lpData
    ** LPDWORD lpcbData


RegEnumValueW
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** DWORD dwIndex
    ** LPWSTR lpValueName
    ** LPDWORD lpcchValueName
    ** LPDWORD lpReserved
    ** LPDWORD lpType
    ** LPBYTE lpData
    ** LPDWORD lpcbData


RegFlushKey
===========

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey


RegGetKeySecurity
=================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** SECURITY_INFORMATION SecurityInformation
    ** PSECURITY_DESCRIPTOR pSecurityDescriptor
    ** LPDWORD lpcbSecurityDescriptor


RegLoadKeyA
===========

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** LPCSTR lpFile


RegLoadKeyW
===========

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** LPCWSTR lpFile


RegNotifyChangeKeyValue
=======================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** BOOL bWatchSubtree
    ** DWORD dwNotifyFilter
    ** HANDLE hEvent
    ** BOOL fAsynchronous


RegOpenCurrentUser
==================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** REGSAM samDesired
    ** PHKEY phkResult


RegOpenKeyExA
=============

Signature::

    * Library: rtmpal
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** DWORD ulOptions
    ** REGSAM samDesired
    ** PHKEY phkResult


RegOpenKeyExW
=============

Signature::

    * Library: rtmpal
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** DWORD ulOptions
    ** REGSAM samDesired
    ** PHKEY phkResult


RegOpenKeyTransactedA
=====================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** DWORD ulOptions
    ** REGSAM samDesired
    ** PHKEY phkResult
    ** HANDLE hTransaction
    ** PVOID pExtendedParemeter


RegOpenKeyTransactedW
=====================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** DWORD ulOptions
    ** REGSAM samDesired
    ** PHKEY phkResult
    ** HANDLE hTransaction
    ** PVOID pExtendedParemeter


RegOpenUserClassesRoot
======================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HANDLE hToken
    ** DWORD dwOptions
    ** REGSAM samDesired
    ** PHKEY phkResult


RegOverridePredefKey
====================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** HKEY hNewHKey


RegQueryMultipleValuesA
=======================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** PVALENTA val_list
    ** DWORD num_vals
    ** LPSTR lpValueBuf
    ** LPDWORD ldwTotsize


RegQueryMultipleValuesW
=======================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** PVALENTW val_list
    ** DWORD num_vals
    ** LPWSTR lpValueBuf
    ** LPDWORD ldwTotsize


RegQueryReflectionKey
=====================

Signature::

    * Library: advapi32
    * Return value: LONG

Parameters::

    ** HKEY hBase
    ** BOOL *bIsReflectionDisabled


RegQueryValueExA
================

Signature::

    * Library: rtmpal
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpValueName
    ** LPDWORD lpReserved
    ** LPDWORD lpType
    ** LPBYTE lpData
    ** LPDWORD lpcbData


RegQueryValueExW
================

Signature::

    * Library: rtmpal
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpValueName
    ** LPDWORD lpReserved
    ** LPDWORD lpType
    ** LPBYTE lpData
    ** LPDWORD lpcbData


RegReplaceKeyA
==============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** LPCSTR lpNewFile
    ** LPCSTR lpOldFile


RegReplaceKeyW
==============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** LPCWSTR lpNewFile
    ** LPCWSTR lpOldFile


RegRestoreKeyA
==============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpFile
    ** DWORD dwFlags


RegRestoreKeyW
==============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpFile
    ** DWORD dwFlags


RegSaveKeyA
===========

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpFile
    ** const LPSECURITY_ATTRIBUTES lpSecurityAttributes


RegSaveKeyW
===========

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpFile
    ** const LPSECURITY_ATTRIBUTES lpSecurityAttributes


RegSaveKeyExA
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpFile
    ** const LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** DWORD Flags


RegSaveKeyExW
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpFile
    ** const LPSECURITY_ATTRIBUTES lpSecurityAttributes
    ** DWORD Flags


RegSetKeySecurity
=================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** SECURITY_INFORMATION SecurityInformation
    ** PSECURITY_DESCRIPTOR pSecurityDescriptor


RegSetKeyValueA
===============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** LPCSTR lpValueName
    ** DWORD dwType
    ** LPCVOID lpData
    ** DWORD cbData


RegSetKeyValueW
===============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** LPCWSTR lpValueName
    ** DWORD dwType
    ** LPCVOID lpData
    ** DWORD cbData


RegSetValueExA
==============

Signature::

    * Library: rtmpal
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpValueName
    ** DWORD Reserved
    ** DWORD dwType
    ** const BYTE *lpData
    ** DWORD cbData


RegSetValueExW
==============

Signature::

    * Library: rtmpal
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpValueName
    ** DWORD Reserved
    ** DWORD dwType
    ** const BYTE *lpData
    ** DWORD cbData


RegUnLoadKeyA
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey


RegUnLoadKeyW
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey


CompareFileTime
===============

Signature::

    * Library: kernel32
    * Return value: LONG

Parameters::

    ** const FILETIME *lpFileTime1
    ** const FILETIME *lpFileTime2


DosDateTimeToFileTime
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** WORD wFatDate
    ** WORD wFatTime
    ** LPFILETIME lpFileTime


EnumDynamicTimeZoneInformation
==============================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** const DWORD dwIndex
    ** PDYNAMIC_TIME_ZONE_INFORMATION lpTimeZoneInformation


FileTimeToLocalFileTime
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const FILETIME *lpFileTime
    ** LPFILETIME lpLocalFileTime


FileTimeToSystemTime
====================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** const FILETIME *lpFileTime
    ** LPSYSTEMTIME lpSystemTime


GetDynamicTimeZoneInformation
=============================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** PDYNAMIC_TIME_ZONE_INFORMATION pTimeZoneInformation


GetDynamicTimeZoneInformationEffectiveYears
===========================================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** const PDYNAMIC_TIME_ZONE_INFORMATION lpTimeZoneInformation
    ** LPDWORD FirstYear
    ** LPDWORD LastYear


GetFileTime
===========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPFILETIME lpCreationTime
    ** LPFILETIME lpLastAccessTime
    ** LPFILETIME lpLastWriteTime


GetLocalTime
============

Signature::

    * Library: rtmpal
    * Return value: void

Parameters::

    ** LPSYSTEMTIME lpSystemTime


GetSystemTime
=============

Signature::

    * Library: rtmpal
    * Return value: void

Parameters::

    ** LPSYSTEMTIME lpSystemTime


GetSystemTimeAdjustment
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PDWORD lpTimeAdjustment
    ** PDWORD lpTimeIncrement
    ** PBOOL lpTimeAdjustmentDisabled


GetSystemTimeAsFileTime
=======================

Signature::

    * Library: rtmpal
    * Return value: void

Parameters::

    ** LPFILETIME lpSystemTimeAsFileTime


GetSystemTimes
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PFILETIME lpIdleTime
    ** PFILETIME lpKernelTime
    ** PFILETIME lpUserTime


GetTickCount
============

Signature::

    * Library: rtmpal
    * Return value: DWORD


GetTickCount64
==============

Signature::

    * Library: rtmpal
    * Return value: ULONGLONG


GetTimeZoneInformation
======================

Signature::

    * Library: rtmpal
    * Return value: DWORD

Parameters::

    ** LPTIME_ZONE_INFORMATION lpTimeZoneInformation


GetTimeZoneInformationForYear
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** USHORT wYear
    ** PDYNAMIC_TIME_ZONE_INFORMATION pdtzi
    ** LPTIME_ZONE_INFORMATION ptzi


LocalFileTimeToFileTime
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const FILETIME *lpLocalFileTime
    ** LPFILETIME lpFileTime


QueryUnbiasedInterruptTime
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PULONGLONG UnbiasedTime


SetDynamicTimeZoneInformation
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const DYNAMIC_TIME_ZONE_INFORMATION *lpTimeZoneInformation


SetFileTime
===========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** const FILETIME *lpCreationTime
    ** const FILETIME *lpLastAccessTime
    ** const FILETIME *lpLastWriteTime


SetLocalTime
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const SYSTEMTIME *lpSystemTime


SetSystemTime
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const SYSTEMTIME *lpSystemTime


SetSystemTimeAdjustment
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwTimeAdjustment
    ** BOOL bTimeAdjustmentDisabled


SetTimeZoneInformation
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const TIME_ZONE_INFORMATION *lpTimeZoneInformation


SystemTimeToFileTime
====================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** const SYSTEMTIME *lpSystemTime
    ** LPFILETIME lpFileTime


SystemTimeToTzSpecificLocalTime
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const TIME_ZONE_INFORMATION *lpTimeZoneInformation
    ** const SYSTEMTIME *lpUniversalTime
    ** LPSYSTEMTIME lpLocalTime


SystemTimeToTzSpecificLocalTimeEx
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const DYNAMIC_TIME_ZONE_INFORMATION *lpTimeZoneInformation
    ** const SYSTEMTIME *lpUniversalTime
    ** LPSYSTEMTIME lpLocalTime


TzSpecificLocalTimeToSystemTime
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const TIME_ZONE_INFORMATION *lpTimeZoneInformation
    ** const SYSTEMTIME *lpLocalTime
    ** LPSYSTEMTIME lpUniversalTime


TzSpecificLocalTimeToSystemTimeEx
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const DYNAMIC_TIME_ZONE_INFORMATION *lpTimeZoneInformation
    ** const SYSTEMTIME *lpLocalTime
    ** LPSYSTEMTIME lpUniversalTime


CallMsgFilterA
==============

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** LPMSG lpMsg
    ** int nCode


CallMsgFilterW
==============

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** LPMSG lpMsg
    ** int nCode


CallNextHookEx
==============

Signature::

    * Library: user32
    * Return value: LRESULT

Parameters::

    ** HHOOK hhk
    ** int nCode
    ** WPARAM wParam
    ** LPARAM lParam


SetWindowsHookExA
=================

Signature::

    * Library: user32
    * Return value: HHOOK

Parameters::

    ** int idHook
    ** HOOKPROC lpfn
    ** HINSTANCE hmod
    ** DWORD dwThreadId


SetWindowsHookExW
=================

Signature::

    * Library: user32
    * Return value: HHOOK

Parameters::

    ** int idHook
    ** HOOKPROC lpfn
    ** HINSTANCE hmod
    ** DWORD dwThreadId


UnhookWindowsHookEx
===================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** HHOOK hhk


CancelWaitableTimer
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hTimer


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


ClosePrivateNamespace
=====================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    ** HANDLE Handle
    ** ULONG Flags


CreatePrivateNamespaceA
=======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpPrivateNamespaceAttributes
    ** LPVOID lpBoundaryDescriptor
    ** LPCSTR lpAliasPrefix


CreatePrivateNamespaceW
=======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpPrivateNamespaceAttributes
    ** LPVOID lpBoundaryDescriptor
    ** LPCWSTR lpAliasPrefix


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


DeleteSynchronizationBarrier
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPSYNCHRONIZATION_BARRIER lpBarrier


DeleteTimerQueue
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE TimerQueue


DeleteTimerQueueEx
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE TimerQueue
    ** HANDLE CompletionEvent


DeleteTimerQueueTimer
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE TimerQueue
    ** HANDLE Timer
    ** HANDLE CompletionEvent


EnterSynchronizationBarrier
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPSYNCHRONIZATION_BARRIER lpBarrier
    ** DWORD dwFlags


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


GetOverlappedResultEx
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPOVERLAPPED lpOverlapped
    ** LPDWORD lpNumberOfBytesTransferred
    ** DWORD dwMilliseconds
    ** BOOL bAlertable


InitializeSynchronizationBarrier
================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPSYNCHRONIZATION_BARRIER lpBarrier
    ** LONG lTotalThreads
    ** LONG lSpinCount


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


OpenMutexA
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCSTR lpName


OpenMutexW
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCWSTR lpName


OpenPrivateNamespaceA
=====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPVOID lpBoundaryDescriptor
    ** LPCSTR lpAliasPrefix


OpenPrivateNamespaceW
=====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPVOID lpBoundaryDescriptor
    ** LPCWSTR lpAliasPrefix


OpenSemaphoreA
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCSTR lpName


OpenSemaphoreW
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCWSTR lpName


OpenWaitableTimerA
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCSTR lpTimerName


OpenWaitableTimerW
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCWSTR lpTimerName


PulseEvent
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hEvent


QueueUserAPC
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** PAPCFUNC pfnAPC
    ** HANDLE hThread
    ** ULONG_PTR dwData

Pre::

    pipe("PROCESS:%d", pid_from_thread_handle(hThread));

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        sleep_skip_disable();
    }


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


ReleaseMutex
============

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hMutex


ReleaseSemaphore
================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hSemaphore
    ** LONG lReleaseCount
    ** LPLONG lpPreviousCount


ResetEvent
==========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hEvent


SetEvent
========

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hEvent


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


SetWaitableTimerEx
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hTimer
    ** const LARGE_INTEGER *lpDueTime
    ** LONG lPeriod
    ** PTIMERAPCROUTINE pfnCompletionRoutine
    ** LPVOID lpArgToCompletionRoutine
    ** PREASON_CONTEXT WakeContext
    ** ULONG TolerableDelay


SignalObjectAndWait
===================

Signature::

    * Library: rtmpal
    * Return value: DWORD

Parameters::

    ** HANDLE hObjectToSignal
    ** HANDLE hObjectToWaitOn
    ** DWORD dwMilliseconds
    ** BOOL bAlertable


SleepConditionVariableCS
========================

Signature::

    * Library: rtmpal
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


UnregisterWait
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE WaitHandle


UnregisterWaitEx
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE WaitHandle
    ** HANDLE CompletionEvent


WaitForMultipleObjects
======================

Signature::

    * Library: rtmpal
    * Return value: DWORD

Parameters::

    ** DWORD nCount
    ** const HANDLE *lpHandles
    ** BOOL bWaitAll
    ** DWORD dwMilliseconds


WaitForMultipleObjectsEx
========================

Signature::

    * Library: rtmpal
    * Return value: DWORD

Parameters::

    ** DWORD nCount
    ** const HANDLE *lpHandles
    ** BOOL bWaitAll
    ** DWORD dwMilliseconds
    ** BOOL bAlertable


WaitForSingleObject
===================

Signature::

    * Library: rtmpal
    * Return value: DWORD

Parameters::

    ** HANDLE hHandle
    ** DWORD dwMilliseconds


WaitForSingleObjectEx
=====================

Signature::

    * Library: rtmpal
    * Return value: DWORD

Parameters::

    ** HANDLE hHandle
    ** DWORD dwMilliseconds
    ** BOOL bAlertable


WakeAllConditionVariable
========================

Signature::

    * Library: rtmpal
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


DnsCancelQuery
==============

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    ** PDNS_QUERY_CANCEL pCancelHandle


DnsFree
=======

Signature::

    * Library: dnsapi
    * Return value: void

Parameters::

    ** PVOID pData
    ** DNS_FREE_TYPE FreeType


DnsFreeProxyName
================

Signature::

    * Library: dnsapi
    * Return value: void

Parameters::

    ** PWSTR proxyName


DnsGetProxyInformation
======================

Signature::

    * Library: dnsapi
    * Return value: DWORD

Parameters::

    ** PCWSTR hostName
    ** DNS_PROXY_INFORMATION *proxyInformation
    ** DNS_PROXY_INFORMATION *defaultProxyInformation
    ** DNS_PROXY_COMPLETION_ROUTINE completionRoutine
    ** void *completionContext


DnsQueryConfig
==============

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    ** DNS_CONFIG_TYPE Config
    ** DWORD Flag
    ** PCWSTR pwsAdapterName
    ** PVOID pReserved
    ** PVOID pBuffer
    ** PDWORD pBufLen


DnsQueryEx
==========

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    ** PDNS_QUERY_REQUEST pQueryRequest
    ** PDNS_QUERY_RESULT pQueryResults
    ** PDNS_QUERY_CANCEL pCancelHandle


DnsRecordCompare
================

Signature::

    * Library: dnsapi
    * Return value: BOOL

Parameters::

    ** PDNS_RECORD pRecord1
    ** PDNS_RECORD pRecord2


DnsRecordCopyEx
===============

Signature::

    * Library: dnsapi
    * Return value: PDNS_RECORD

Parameters::

    ** PDNS_RECORD pRecord
    ** DNS_CHARSET CharSetIn
    ** DNS_CHARSET CharSetOut


DnsRecordListFree
=================

Signature::

    * Library: dnsapi
    * Return value: void

Parameters::

    ** PDNS_RECORD pRecordList
    ** DNS_FREE_TYPE FreeType


DnsRecordSetCompare
===================

Signature::

    * Library: dnsapi
    * Return value: BOOL

Parameters::

    ** PDNS_RECORD pRR1
    ** PDNS_RECORD pRR2
    ** PDNS_RECORD *ppDiff1
    ** PDNS_RECORD *ppDiff2


DnsRecordSetCopyEx
==================

Signature::

    * Library: dnsapi
    * Return value: PDNS_RECORD

Parameters::

    ** PDNS_RECORD pRecordSet
    ** DNS_CHARSET CharSetIn
    ** DNS_CHARSET CharSetOut


DnsReleaseContextHandle
=======================

Signature::

    * Library: dnsapi
    * Return value: void

Parameters::

    ** HANDLE hContext


DnsReplaceRecordSetA
====================

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    ** PDNS_RECORD pReplaceSet
    ** DWORD Options
    ** HANDLE hContext
    ** PVOID pExtraInfo
    ** PVOID pReserved


DnsReplaceRecordSetW
====================

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    ** PDNS_RECORD pReplaceSet
    ** DWORD Options
    ** HANDLE hContext
    ** PVOID pExtraInfo
    ** PVOID pReserved


FindNextUrlCacheEntryA
======================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HANDLE hEnumHandle
    ** LPINTERNET_CACHE_ENTRY_INFOA lpNextCacheEntryInfo
    ** LPDWORD lpcbCacheEntryInfo


FindNextUrlCacheEntryW
======================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HANDLE hEnumHandle
    ** LPINTERNET_CACHE_ENTRY_INFOW lpNextCacheEntryInfo
    ** LPDWORD lpcbCacheEntryInfo


FindNextUrlCacheEntryExA
========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HANDLE hEnumHandle
    ** LPINTERNET_CACHE_ENTRY_INFOA lpNextCacheEntryInfo
    ** LPDWORD lpcbCacheEntryInfo
    ** LPVOID lpGroupAttributes
    ** LPDWORD lpcbGroupAttributes
    ** LPVOID lpReserved


FindNextUrlCacheEntryExW
========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HANDLE hEnumHandle
    ** LPINTERNET_CACHE_ENTRY_INFOW lpNextCacheEntryInfo
    ** LPDWORD lpcbCacheEntryInfo
    ** LPVOID lpGroupAttributes
    ** LPDWORD lpcbGroupAttributes
    ** LPVOID lpReserved


FreeAddrInfoEx
==============

Signature::

    * Library: ws2_32
    * Return value: void

Parameters::

    ** PADDRINFOEXA pAddrInfoEx


FreeAddrInfoExW
===============

Signature::

    * Library: ws2_32
    * Return value: void

Parameters::

    ** PADDRINFOEXW pAddrInfoEx


FreeAddrInfoW
=============

Signature::

    * Library: ws2_32
    * Return value: void

Parameters::

    ** PADDRINFOW pAddrInfo


GetAddrInfoExCancel
===================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPHANDLE lpHandle


GetAddrInfoExOverlappedResult
=============================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPOVERLAPPED lpOverlapped


GetHostNameW
============

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** PWSTR name
    ** int namelen


GetNameInfoW
============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** const SOCKADDR *pSockaddr
    ** socklen_t SockaddrLength
    ** PWCHAR pNodeBuffer
    ** DWORD NodeBufferSize
    ** PWCHAR pServiceBuffer
    ** DWORD ServiceBufferSize
    ** INT Flags


HttpAddFragmentToCache
======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** PCWSTR pUrlPrefix
    ** PHTTP_DATA_CHUNK pDataChunk
    ** PHTTP_CACHE_POLICY pCachePolicy
    ** LPOVERLAPPED pOverlapped


HttpAddUrl
==========

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** PCWSTR pFullyQualifiedUrl
    ** PVOID pReserved


HttpAddUrlToUrlGroup
====================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTP_URL_GROUP_ID UrlGroupId
    ** PCWSTR pFullyQualifiedUrl
    ** HTTP_URL_CONTEXT UrlContext
    ** ULONG Reserved


HttpCloseRequestQueue
=====================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle


HttpCloseServerSession
======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTP_SERVER_SESSION_ID ServerSessionId


HttpCloseUrlGroup
=================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTP_URL_GROUP_ID UrlGroupId


HttpCreateHttpHandle
====================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** PHANDLE pReqQueueHandle
    ** ULONG Reserved


HttpCreateRequestQueue
======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTPAPI_VERSION Version
    ** PCWSTR pName
    ** PSECURITY_ATTRIBUTES pSecurityAttributes
    ** ULONG Flags
    ** PHANDLE pReqQueueHandle


HttpCreateServerSession
=======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTPAPI_VERSION Version
    ** PHTTP_SERVER_SESSION_ID pServerSessionId
    ** ULONG Reserved


HttpCreateUrlGroup
==================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTP_SERVER_SESSION_ID ServerSessionId
    ** PHTTP_URL_GROUP_ID pUrlGroupId
    ** ULONG Reserved


HttpDeleteServiceConfiguration
==============================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ServiceHandle
    ** HTTP_SERVICE_CONFIG_ID ConfigId
    ** PVOID pConfigInformation
    ** ULONG ConfigInformationLength
    ** LPOVERLAPPED pOverlapped


HttpFlushResponseCache
======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** PCWSTR pUrlPrefix
    ** ULONG Flags
    ** LPOVERLAPPED pOverlapped


HttpInitialize
==============

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTPAPI_VERSION Version
    ** ULONG Flags
    ** PVOID pReserved


HttpPrepareUrl
==============

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** PVOID Reserved
    ** ULONG Flags
    ** PCWSTR Url
    ** PWSTR *PreparedUrl


HttpQueryInfoA
==============

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hRequest
    ** DWORD dwInfoLevel
    ** LPVOID lpBuffer
    ** LPDWORD lpdwBufferLength
    ** LPDWORD lpdwIndex


HttpQueryInfoW
==============

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hRequest
    ** DWORD dwInfoLevel
    ** LPVOID lpBuffer
    ** LPDWORD lpdwBufferLength
    ** LPDWORD lpdwIndex


HttpQueryRequestQueueProperty
=============================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE Handle
    ** HTTP_SERVER_PROPERTY Property
    ** PVOID pPropertyInformation
    ** ULONG PropertyInformationLength
    ** ULONG Reserved
    ** PULONG pReturnLength
    ** PVOID pReserved


HttpQueryServerSessionProperty
==============================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTP_SERVER_SESSION_ID ServerSessionId
    ** HTTP_SERVER_PROPERTY Property
    ** PVOID pPropertyInformation
    ** ULONG PropertyInformationLength
    ** PULONG pReturnLength


HttpQueryServiceConfiguration
=============================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ServiceHandle
    ** HTTP_SERVICE_CONFIG_ID ConfigId
    ** PVOID pInput
    ** ULONG InputLength
    ** PVOID pOutput
    ** ULONG OutputLength
    ** PULONG pReturnLength
    ** LPOVERLAPPED pOverlapped


HttpQueryUrlGroupProperty
=========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTP_URL_GROUP_ID UrlGroupId
    ** HTTP_SERVER_PROPERTY Property
    ** PVOID pPropertyInformation
    ** ULONG PropertyInformationLength
    ** PULONG pReturnLength


HttpReadFragmentFromCache
=========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** PCWSTR pUrlPrefix
    ** PHTTP_BYTE_RANGE pByteRange
    ** PVOID pBuffer
    ** ULONG BufferLength
    ** PULONG pBytesRead
    ** LPOVERLAPPED pOverlapped


HttpReceiveClientCertificate
============================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** HTTP_CONNECTION_ID ConnectionId
    ** ULONG Flags
    ** PHTTP_SSL_CLIENT_CERT_INFO pSslClientCertInfo
    ** ULONG SslClientCertInfoSize
    ** PULONG pBytesReceived
    ** LPOVERLAPPED pOverlapped


HttpReceiveHttpRequest
======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** HTTP_REQUEST_ID RequestId
    ** ULONG Flags
    ** PHTTP_REQUEST pRequestBuffer
    ** ULONG RequestBufferLength
    ** PULONG pBytesReturned
    ** LPOVERLAPPED pOverlapped


HttpReceiveRequestEntityBody
============================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** HTTP_REQUEST_ID RequestId
    ** ULONG Flags
    ** PVOID pBuffer
    ** ULONG EntityBufferLength
    ** PULONG pBytesReturned
    ** LPOVERLAPPED pOverlapped


HttpRemoveUrl
=============

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** PCWSTR pFullyQualifiedUrl


HttpRemoveUrlFromUrlGroup
=========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTP_URL_GROUP_ID UrlGroupId
    ** PCWSTR pFullyQualifiedUrl
    ** ULONG Flags


HttpSendHttpResponse
====================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** HTTP_REQUEST_ID RequestId
    ** ULONG Flags
    ** PHTTP_RESPONSE pHttpResponse
    ** PHTTP_CACHE_POLICY pCachePolicy
    ** PULONG pBytesSent
    ** PVOID pReserved1
    ** ULONG Reserved2
    ** LPOVERLAPPED pOverlapped
    ** PHTTP_LOG_DATA pLogData


HttpSendResponseEntityBody
==========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** HTTP_REQUEST_ID RequestId
    ** ULONG Flags
    ** USHORT EntityChunkCount
    ** PHTTP_DATA_CHUNK pEntityChunks
    ** PULONG pBytesSent
    ** PVOID pReserved1
    ** ULONG Reserved2
    ** LPOVERLAPPED pOverlapped
    ** PHTTP_LOG_DATA pLogData


HttpSetRequestQueueProperty
===========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE Handle
    ** HTTP_SERVER_PROPERTY Property
    ** PVOID pPropertyInformation
    ** ULONG PropertyInformationLength
    ** ULONG Reserved
    ** PVOID pReserved


HttpSetServerSessionProperty
============================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTP_SERVER_SESSION_ID ServerSessionId
    ** HTTP_SERVER_PROPERTY Property
    ** PVOID pPropertyInformation
    ** ULONG PropertyInformationLength


HttpSetServiceConfiguration
===========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ServiceHandle
    ** HTTP_SERVICE_CONFIG_ID ConfigId
    ** PVOID pConfigInformation
    ** ULONG ConfigInformationLength
    ** LPOVERLAPPED pOverlapped


HttpSetUrlGroupProperty
=======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTP_URL_GROUP_ID UrlGroupId
    ** HTTP_SERVER_PROPERTY Property
    ** PVOID pPropertyInformation
    ** ULONG PropertyInformationLength


HttpShutdownRequestQueue
========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle


HttpTerminate
=============

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** ULONG Flags
    ** PVOID pReserved


HttpWaitForDemandStart
======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** LPOVERLAPPED pOverlapped


HttpWaitForDisconnect
=====================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** HTTP_CONNECTION_ID ConnectionId
    ** LPOVERLAPPED pOverlapped


IcmpCloseHandle
===============

Signature::

    * Library: icmp
    * Return value: BOOL

Parameters::

    ** HANDLE IcmpHandle


IcmpCreateFile
==============

Signature::

    * Library: icmp
    * Return value: HANDLE


IcmpParseReplies
================

Signature::

    * Library: icmp
    * Return value: DWORD

Parameters::

    ** LPVOID ReplyBuffer
    ** DWORD ReplySize


IcmpSendEcho
============

Signature::

    * Library: icmp
    * Return value: DWORD

Parameters::

    ** HANDLE IcmpHandle
    ** IPAddr DestinationAddress
    ** LPVOID RequestData
    ** WORD RequestSize
    ** PIP_OPTION_INFORMATION RequestOptions
    ** LPVOID ReplyBuffer
    ** DWORD ReplySize
    ** DWORD Timeout


InetNtopW
=========

Signature::

    * Library: ws2_32
    * Return value: PCWSTR

Parameters::

    ** INT Family
    ** PVOID pAddr
    ** PWSTR pStringBuf
    ** size_t StringBufSize


InetPtonW
=========

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** INT Family
    ** PCWSTR pszAddrString
    ** PVOID pAddrBuf


InternetCanonicalizeUrlA
========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrl
    ** LPSTR lpszBuffer
    ** LPDWORD lpdwBufferLength
    ** DWORD dwFlags


InternetCanonicalizeUrlW
========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszUrl
    ** LPWSTR lpszBuffer
    ** LPDWORD lpdwBufferLength
    ** DWORD dwFlags


InternetCheckConnectionA
========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrl
    ** DWORD dwFlags
    ** DWORD dwReserved


InternetCheckConnectionW
========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszUrl
    ** DWORD dwFlags
    ** DWORD dwReserved


InternetCombineUrlA
===================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszBaseUrl
    ** LPCSTR lpszRelativeUrl
    ** LPSTR lpszBuffer
    ** LPDWORD lpdwBufferLength
    ** DWORD dwFlags


InternetCombineUrlW
===================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszBaseUrl
    ** LPCWSTR lpszRelativeUrl
    ** LPWSTR lpszBuffer
    ** LPDWORD lpdwBufferLength
    ** DWORD dwFlags


InternetCrackUrlA
=================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrl
    ** DWORD dwUrlLength
    ** DWORD dwFlags
    ** LPURL_COMPONENTSA lpUrlComponents


InternetCrackUrlW
=================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszUrl
    ** DWORD dwUrlLength
    ** DWORD dwFlags
    ** LPURL_COMPONENTSW lpUrlComponents


InternetGetCookieA
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrl
    ** LPCSTR lpszCookieName
    ** LPSTR lpszCookieData
    ** LPDWORD lpdwSize


InternetGetCookieW
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszUrl
    ** LPCWSTR lpszCookieName
    ** LPWSTR lpszCookieData
    ** LPDWORD lpdwSize


InternetGetCookieExA
====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrl
    ** LPCSTR lpszCookieName
    ** LPSTR lpszCookieData
    ** LPDWORD lpdwSize
    ** DWORD dwFlags
    ** LPVOID lpReserved


InternetGetCookieExW
====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszUrl
    ** LPCWSTR lpszCookieName
    ** LPWSTR lpszCookieData
    ** LPDWORD lpdwSize
    ** DWORD dwFlags
    ** LPVOID lpReserved


InternetGetLastResponseInfoA
============================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPDWORD lpdwError
    ** LPSTR lpszBuffer
    ** LPDWORD lpdwBufferLength


InternetGetLastResponseInfoW
============================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPDWORD lpdwError
    ** LPWSTR lpszBuffer
    ** LPDWORD lpdwBufferLength


InternetSetCookieA
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrl
    ** LPCSTR lpszCookieName
    ** LPCSTR lpszCookieData


InternetSetCookieW
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszUrl
    ** LPCWSTR lpszCookieName
    ** LPCWSTR lpszCookieData


ReadUrlCacheEntryStream
=======================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HANDLE hUrlCacheStream
    ** DWORD dwLocation
    ** LPVOID lpBuffer
    ** LPDWORD lpdwLen
    ** DWORD Reserved


RetrieveUrlCacheEntryFileA
==========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrlName
    ** LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo
    ** LPDWORD lpcbCacheEntryInfo
    ** DWORD dwReserved


RetrieveUrlCacheEntryFileW
==========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszUrlName
    ** LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo
    ** LPDWORD lpcbCacheEntryInfo
    ** DWORD dwReserved


RpcCertGeneratePrincipalNameA
=============================

Signature::

    * Library: rpcrt4
    * Return value: RPC_STATUS

Parameters::

    ** PCCERT_CONTEXT Context
    ** DWORD Flags
    ** RPC_CSTR *pBuffer


RpcCertGeneratePrincipalNameW
=============================

Signature::

    * Library: rpcrt4
    * Return value: RPC_STATUS

Parameters::

    ** PCCERT_CONTEXT Context
    ** DWORD Flags
    ** RPC_WSTR *pBuffer


SetAddrInfoExA
==============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** PCSTR pName
    ** PCSTR pServiceName
    ** SOCKET_ADDRESS *pAddresses
    ** DWORD dwAddressCount
    ** LPBLOB lpBlob
    ** DWORD dwFlags
    ** DWORD dwNameSpace
    ** LPGUID lpNspId
    ** struct timeval *timeout
    ** LPOVERLAPPED lpOverlapped
    ** LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine
    ** LPHANDLE lpNameHandle


SetAddrInfoExW
==============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** PCWSTR pName
    ** PCWSTR pServiceName
    ** SOCKET_ADDRESS *pAddresses
    ** DWORD dwAddressCount
    ** LPBLOB lpBlob
    ** DWORD dwFlags
    ** DWORD dwNameSpace
    ** LPGUID lpNspId
    ** struct timeval *timeout
    ** LPOVERLAPPED lpOverlapped
    ** LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine
    ** LPHANDLE lpNameHandle


UnlockUrlCacheEntryStream
=========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HANDLE hUrlCacheStream
    ** DWORD Reserved


WSAAccept
=========

Signature::

    * Library: ws2_32
    * Return value: SOCKET

Parameters::

    ** SOCKET s
    ** struct sockaddr *addr
    ** LPINT addrlen
    ** LPCONDITIONPROC lpfnCondition
    ** DWORD_PTR dwCallbackData


WSAAddressToStringA
===================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPSOCKADDR lpsaAddress
    ** DWORD dwAddressLength
    ** LPWSAPROTOCOL_INFOA lpProtocolInfo
    ** LPSTR lpszAddressString
    ** LPDWORD lpdwAddressStringLength


WSAAddressToStringW
===================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPSOCKADDR lpsaAddress
    ** DWORD dwAddressLength
    ** LPWSAPROTOCOL_INFOW lpProtocolInfo
    ** LPWSTR lpszAddressString
    ** LPDWORD lpdwAddressStringLength


WSAAsyncGetHostByAddr
=====================

Signature::

    * Library: wsock32
    * Return value: HANDLE

Parameters::

    ** HWND hWnd
    ** u_int wMsg
    ** const char *addr
    ** int len
    ** int type
    ** char *buf
    ** int buflen


WSAAsyncGetHostByName
=====================

Signature::

    * Library: wsock32
    * Return value: HANDLE

Parameters::

    ** HWND hWnd
    ** u_int wMsg
    ** const char *name
    ** char *buf
    ** int buflen


WSAAsyncGetProtoByName
======================

Signature::

    * Library: wsock32
    * Return value: HANDLE

Parameters::

    ** HWND hWnd
    ** u_int wMsg
    ** const char *name
    ** char *buf
    ** int buflen


WSAAsyncGetProtoByNumber
========================

Signature::

    * Library: wsock32
    * Return value: HANDLE

Parameters::

    ** HWND hWnd
    ** u_int wMsg
    ** int number
    ** char *buf
    ** int buflen


WSAAsyncGetServByName
=====================

Signature::

    * Library: wsock32
    * Return value: HANDLE

Parameters::

    ** HWND hWnd
    ** u_int wMsg
    ** const char *name
    ** const char *proto
    ** char *buf
    ** int buflen


WSAAsyncGetServByPort
=====================

Signature::

    * Library: wsock32
    * Return value: HANDLE

Parameters::

    ** HWND hWnd
    ** u_int wMsg
    ** int port
    ** const char *proto
    ** char *buf
    ** int buflen


WSAAsyncSelect
==============

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** HWND hWnd
    ** u_int wMsg
    ** long lEvent


WSACancelAsyncRequest
=====================

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** HANDLE hAsyncTaskHandle


WSACloseEvent
=============

Signature::

    * Library: ws2_32
    * Return value: BOOL

Parameters::

    ** WSAEVENT hEvent


WSAConnect
==========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** const struct sockaddr *name
    ** int namelen
    ** LPWSABUF lpCallerData
    ** LPWSABUF lpCalleeData
    ** LPQOS lpSQOS
    ** LPQOS lpGQOS


WSADuplicateSocketA
===================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** DWORD dwProcessId
    ** LPWSAPROTOCOL_INFOA lpProtocolInfo


WSADuplicateSocketW
===================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** DWORD dwProcessId
    ** LPWSAPROTOCOL_INFOW lpProtocolInfo


WSAEnumNameSpaceProvidersA
==========================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPDWORD lpdwBufferLength
    ** LPWSANAMESPACE_INFOA lpnspBuffer


WSAEnumNameSpaceProvidersW
==========================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPDWORD lpdwBufferLength
    ** LPWSANAMESPACE_INFOW lpnspBuffer


WSAEnumNameSpaceProvidersExA
============================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPDWORD lpdwBufferLength
    ** LPWSANAMESPACE_INFOEXA lpnspBuffer


WSAEnumNameSpaceProvidersExW
============================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPDWORD lpdwBufferLength
    ** LPWSANAMESPACE_INFOEXW lpnspBuffer


WSAEnumNetworkEvents
====================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** WSAEVENT hEventObject
    ** LPWSANETWORKEVENTS lpNetworkEvents


WSAEnumProtocolsA
=================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** LPINT lpiProtocols
    ** LPWSAPROTOCOL_INFOA lpProtocolBuffer
    ** LPDWORD lpdwBufferLength


WSAEnumProtocolsW
=================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** LPINT lpiProtocols
    ** LPWSAPROTOCOL_INFOW lpProtocolBuffer
    ** LPDWORD lpdwBufferLength


WSAEventSelect
==============

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** WSAEVENT hEventObject
    ** long lNetworkEvents


WSAGetOverlappedResult
======================

Signature::

    * Library: ws2_32
    * Return value: BOOL

Parameters::

    ** SOCKET s
    ** LPWSAOVERLAPPED lpOverlapped
    ** LPDWORD lpcbTransfer
    ** BOOL fWait
    ** LPDWORD lpdwFlags


WSAGetQOSByName
===============

Signature::

    * Library: ws2_32
    * Return value: BOOL

Parameters::

    ** SOCKET s
    ** LPWSABUF lpQOSName
    ** LPQOS lpQOS


WSAGetServiceClassInfoA
=======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPGUID lpProviderId
    ** LPGUID lpServiceClassId
    ** LPDWORD lpdwBufSize
    ** LPWSASERVICECLASSINFOA lpServiceClassInfo


WSAGetServiceClassInfoW
=======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPGUID lpProviderId
    ** LPGUID lpServiceClassId
    ** LPDWORD lpdwBufSize
    ** LPWSASERVICECLASSINFOW lpServiceClassInfo


WSAGetServiceClassNameByClassIdA
================================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPGUID lpServiceClassId
    ** LPSTR lpszServiceClassName
    ** LPDWORD lpdwBufferLength


WSAGetServiceClassNameByClassIdW
================================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPGUID lpServiceClassId
    ** LPWSTR lpszServiceClassName
    ** LPDWORD lpdwBufferLength


WSAHtonl
========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** u_long hostlong
    ** u_long *lpnetlong


WSAHtons
========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** u_short hostshort
    ** u_short *lpnetshort


WSAInstallServiceClassA
=======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPWSASERVICECLASSINFOA lpServiceClassInfo


WSAInstallServiceClassW
=======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPWSASERVICECLASSINFOW lpServiceClassInfo


WSAIoctl
========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** DWORD dwIoControlCode
    ** LPVOID lpvInBuffer
    ** DWORD cbInBuffer
    ** LPVOID lpvOutBuffer
    ** DWORD cbOutBuffer
    ** LPDWORD lpcbBytesReturned
    ** LPWSAOVERLAPPED lpOverlapped
    ** LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


WSAJoinLeaf
===========

Signature::

    * Library: ws2_32
    * Return value: SOCKET

Parameters::

    ** SOCKET s
    ** const struct sockaddr *name
    ** int namelen
    ** LPWSABUF lpCallerData
    ** LPWSABUF lpCalleeData
    ** LPQOS lpSQOS
    ** LPQOS lpGQOS
    ** DWORD dwFlags


WSALookupServiceBeginA
======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPWSAQUERYSETA lpqsRestrictions
    ** DWORD dwControlFlags
    ** LPHANDLE lphLookup


WSALookupServiceBeginW
======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPWSAQUERYSETW lpqsRestrictions
    ** DWORD dwControlFlags
    ** LPHANDLE lphLookup


WSALookupServiceEnd
===================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** HANDLE hLookup


WSALookupServiceNextA
=====================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** HANDLE hLookup
    ** DWORD dwControlFlags
    ** LPDWORD lpdwBufferLength
    ** LPWSAQUERYSETA lpqsResults


WSALookupServiceNextW
=====================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** HANDLE hLookup
    ** DWORD dwControlFlags
    ** LPDWORD lpdwBufferLength
    ** LPWSAQUERYSETW lpqsResults


WSANSPIoctl
===========

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** HANDLE hLookup
    ** DWORD dwControlCode
    ** LPVOID lpvInBuffer
    ** DWORD cbInBuffer
    ** LPVOID lpvOutBuffer
    ** DWORD cbOutBuffer
    ** LPDWORD lpcbBytesReturned
    ** LPWSACOMPLETION lpCompletion


WSANtohl
========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** u_long netlong
    ** u_long *lphostlong


WSANtohs
========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** u_short netshort
    ** u_short *lphostshort


WSAPoll
=======

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** LPWSAPOLLFD fdArray
    ** ULONG fds
    ** INT timeout


WSAProviderConfigChange
=======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPHANDLE lpNotificationHandle
    ** LPWSAOVERLAPPED lpOverlapped
    ** LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


WSARecv
=======

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** LPWSABUF lpBuffers
    ** DWORD dwBufferCount
    ** LPDWORD lpNumberOfBytesRecvd
    ** LPDWORD lpFlags
    ** LPWSAOVERLAPPED lpOverlapped
    ** LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


WSARecvDisconnect
=================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** LPWSABUF lpInboundDisconnectData


WSARecvFrom
===========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** LPWSABUF lpBuffers
    ** DWORD dwBufferCount
    ** LPDWORD lpNumberOfBytesRecvd
    ** LPDWORD lpFlags
    ** struct sockaddr *lpFrom
    ** LPINT lpFromlen
    ** LPWSAOVERLAPPED lpOverlapped
    ** LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


WSARemoveServiceClass
=====================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPGUID lpServiceClassId


WSAResetEvent
=============

Signature::

    * Library: ws2_32
    * Return value: BOOL

Parameters::

    ** WSAEVENT hEvent


WSASend
=======

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** LPWSABUF lpBuffers
    ** DWORD dwBufferCount
    ** LPDWORD lpNumberOfBytesSent
    ** DWORD dwFlags
    ** LPWSAOVERLAPPED lpOverlapped
    ** LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


WSASendDisconnect
=================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** LPWSABUF lpOutboundDisconnectData


WSASendTo
=========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** LPWSABUF lpBuffers
    ** DWORD dwBufferCount
    ** LPDWORD lpNumberOfBytesSent
    ** DWORD dwFlags
    ** const struct sockaddr *lpTo
    ** int iTolen
    ** LPWSAOVERLAPPED lpOverlapped
    ** LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


WSASetEvent
===========

Signature::

    * Library: ws2_32
    * Return value: BOOL

Parameters::

    ** WSAEVENT hEvent


WSASetLastError
===============

Signature::

    * Library: wsock32
    * Return value: void

Parameters::

    ** int iError


WSASetServiceA
==============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPWSAQUERYSETA lpqsRegInfo
    ** WSAESETSERVICEOP essoperation
    ** DWORD dwControlFlags


WSASetServiceW
==============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPWSAQUERYSETW lpqsRegInfo
    ** WSAESETSERVICEOP essoperation
    ** DWORD dwControlFlags


WSASocketA
==========

Signature::

    * Library: ws2_32
    * Return value: SOCKET

Parameters::

    ** int af
    ** int type
    ** int protocol
    ** LPWSAPROTOCOL_INFOA lpProtocolInfo
    ** GROUP g
    ** DWORD dwFlags


WSASocketW
==========

Signature::

    * Library: ws2_32
    * Return value: SOCKET

Parameters::

    ** int af
    ** int type
    ** int protocol
    ** LPWSAPROTOCOL_INFOW lpProtocolInfo
    ** GROUP g
    ** DWORD dwFlags


WSAStartup
==========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** WORD wVersionRequested
    ** LPWSADATA lpWSAData


WSAStringToAddressA
===================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPSTR AddressString
    ** INT AddressFamily
    ** LPWSAPROTOCOL_INFOA lpProtocolInfo
    ** LPSOCKADDR lpAddress
    ** LPINT lpAddressLength


WSAStringToAddressW
===================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPWSTR AddressString
    ** INT AddressFamily
    ** LPWSAPROTOCOL_INFOW lpProtocolInfo
    ** LPSOCKADDR lpAddress
    ** LPINT lpAddressLength


WSAWaitForMultipleEvents
========================

Signature::

    * Library: ws2_32
    * Return value: DWORD

Parameters::

    ** DWORD cEvents
    ** const WSAEVENT *lphEvents
    ** BOOL fWaitAll
    ** DWORD dwTimeout
    ** BOOL fAlertable


accept
======

Signature::

    * Library: wsock32
    * Return value: SOCKET

Parameters::

    ** SOCKET s
    ** struct sockaddr *addr
    ** int *addrlen


bind
====

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** const struct sockaddr *name
    ** int namelen


closesocket
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s


connect
=======

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** const struct sockaddr *name
    ** int namelen


freeaddrinfo
============

Signature::

    * Library: ws2_32
    * Return value: void

Parameters::

    ** PADDRINFOA pAddrInfo


gethostbyaddr
=============

Signature::

    * Library: wsock32
    * Return value: struct hostent FAR *

Parameters::

    ** const char *addr
    ** int len
    ** int type


gethostbyname
=============

Signature::

    * Library: wsock32
    * Return value: struct hostent FAR *

Parameters::

    ** const char *name


gethostname
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** char *name
    ** int namelen


getnameinfo
===========

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** const SOCKADDR *pSockaddr
    ** socklen_t SockaddrLength
    ** PCHAR pNodeBuffer
    ** DWORD NodeBufferSize
    ** PCHAR pServiceBuffer
    ** DWORD ServiceBufferSize
    ** INT Flags


getpeername
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** struct sockaddr *name
    ** int *namelen


getprotobyname
==============

Signature::

    * Library: wsock32
    * Return value: struct protoent FAR *

Parameters::

    ** const char *name


getprotobynumber
================

Signature::

    * Library: wsock32
    * Return value: struct protoent FAR *

Parameters::

    ** int number


getservbyname
=============

Signature::

    * Library: wsock32
    * Return value: struct servent FAR *

Parameters::

    ** const char *name
    ** const char *proto


getservbyport
=============

Signature::

    * Library: wsock32
    * Return value: struct servent FAR *

Parameters::

    ** int port
    ** const char *proto


getsockname
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** struct sockaddr *name
    ** int *namelen


getsockopt
==========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** int level
    ** int optname
    ** char *optval
    ** int *optlen


htonl
=====

Signature::

    * Library: wsock32
    * Return value: u_long

Parameters::

    ** u_long hostlong


htons
=====

Signature::

    * Library: wsock32
    * Return value: u_short

Parameters::

    ** u_short hostshort


inet_addr
=========

Signature::

    * Library: wsock32
    * Return value: unsigned long

Parameters::

    ** const char *cp


inet_ntoa
=========

Signature::

    * Library: wsock32
    * Return value: char FAR *

Parameters::

    ** struct in_addr in


ioctlsocket
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** long cmd
    ** u_long *argp


listen
======

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** int backlog


ntohl
=====

Signature::

    * Library: wsock32
    * Return value: u_long

Parameters::

    ** u_long netlong


ntohs
=====

Signature::

    * Library: wsock32
    * Return value: u_short

Parameters::

    ** u_short netshort


recv
====

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** char *buf
    ** int len
    ** int flags


recvfrom
========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** char *buf
    ** int len
    ** int flags
    ** struct sockaddr *from
    ** int *fromlen


select
======

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** int nfds
    ** fd_set *readfds
    ** fd_set *writefds
    ** fd_set *exceptfds
    ** const struct timeval *timeout


send
====

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** const char *buf
    ** int len
    ** int flags


sendto
======

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** const char *buf
    ** int len
    ** int flags
    ** const struct sockaddr *to
    ** int tolen


setsockopt
==========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** int level
    ** int optname
    ** const char *optval
    ** int optlen


shutdown
========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** int how


socket
======

Signature::

    * Library: wsock32
    * Return value: SOCKET

Parameters::

    ** int af
    ** int type
    ** int protocol


URLDownloadToFileW
==================

Signature::

    * Library: urlmon
    * Return value: HRESULT

Parameters::

    *  LPUNKNOWN pCaller
    ** LPWSTR szURL url
    *  LPWSTR szFileName
    *  DWORD dwReserved
    *  LPBINDSTATUSCALLBACK lpfnCB

Interesting::

    u url
    u filepath

Pre::

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(szFileName, filepath);

Logging::

    u filepath filepath
    u filepath_r szFileName

Post::

    if(ret == S_OK) {
        pipe("FILE_NEW:%Z", filepath);
    }

    free_unicode_buffer(filepath);


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


AssignProcessToJobObject
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hJob
    ** HANDLE hProcess


AttachThreadInput
=================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** DWORD idAttach
    ** DWORD idAttachTo
    ** BOOL fAttach


AvQuerySystemResponsiveness
===========================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** HANDLE AvrtHandle
    ** PULONG SystemResponsivenessValue


AvRevertMmThreadCharacteristics
===============================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** HANDLE AvrtHandle


AvRtCreateThreadOrderingGroup
=============================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** PHANDLE Context
    ** PLARGE_INTEGER Period
    ** GUID *ThreadOrderingGuid
    ** PLARGE_INTEGER Timeout


AvRtCreateThreadOrderingGroupExA
================================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** PHANDLE Context
    ** PLARGE_INTEGER Period
    ** GUID *ThreadOrderingGuid
    ** PLARGE_INTEGER Timeout
    ** LPCSTR TaskName


AvRtCreateThreadOrderingGroupExW
================================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** PHANDLE Context
    ** PLARGE_INTEGER Period
    ** GUID *ThreadOrderingGuid
    ** PLARGE_INTEGER Timeout
    ** LPCWSTR TaskName


AvRtDeleteThreadOrderingGroup
=============================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** HANDLE Context


AvRtJoinThreadOrderingGroup
===========================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** PHANDLE Context
    ** GUID *ThreadOrderingGuid
    ** BOOL Before


AvRtLeaveThreadOrderingGroup
============================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** HANDLE Context


AvRtWaitOnThreadOrderingGroup
=============================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** HANDLE Context


AvSetMmMaxThreadCharacteristicsA
================================

Signature::

    * Library: avrt
    * Return value: HANDLE

Parameters::

    ** LPCSTR FirstTask
    ** LPCSTR SecondTask
    ** LPDWORD TaskIndex


AvSetMmMaxThreadCharacteristicsW
================================

Signature::

    * Library: avrt
    * Return value: HANDLE

Parameters::

    ** LPCWSTR FirstTask
    ** LPCWSTR SecondTask
    ** LPDWORD TaskIndex


AvSetMmThreadCharacteristicsA
=============================

Signature::

    * Library: avrt
    * Return value: HANDLE

Parameters::

    ** LPCSTR TaskName
    ** LPDWORD TaskIndex


AvSetMmThreadCharacteristicsW
=============================

Signature::

    * Library: avrt
    * Return value: HANDLE

Parameters::

    ** LPCWSTR TaskName
    ** LPDWORD TaskIndex


AvSetMmThreadPriority
=====================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** HANDLE AvrtHandle
    ** AVRT_PRIORITY Priority


BindIoCompletionCallback
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE FileHandle
    ** LPOVERLAPPED_COMPLETION_ROUTINE Function
    ** ULONG Flags


CallbackMayRunLong
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_CALLBACK_INSTANCE pci


CancelThreadpoolIo
==================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_IO pio


CloseThreadpool
===============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_POOL ptpp


CloseThreadpoolCleanupGroup
===========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CLEANUP_GROUP ptpcg


CloseThreadpoolCleanupGroupMembers
==================================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CLEANUP_GROUP ptpcg
    ** BOOL fCancelPendingCallbacks
    ** PVOID pvCleanupContext


CloseThreadpoolIo
=================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_IO pio


CloseThreadpoolTimer
====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_TIMER pti


CloseThreadpoolWait
===================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WAIT pwa


CloseThreadpoolWork
===================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WORK pwk


ConvertFiberToThread
====================

Signature::

    * Library: kernel32
    * Return value: BOOL


ConvertThreadToFiber
====================

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

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

Middle::

    uint32_t pid = lpProcessInformation->dwProcessId;

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        pipe("PROCESS:%d", pid);
        sleep_skip_disable();
    }


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

Middle::

    uint32_t pid = lpProcessInformation->dwProcessId;

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        pipe("PROCESS:%d", pid);
        sleep_skip_disable();
    }


CreateProcessInternalW
======================

Signature::

    * Library: kernel32
    * Logging: always
    * Mode: exploit
    * Return value: BOOL
    * Special: true

Parameters::

    *  LPVOID lpUnknown1
    *  LPWSTR lpApplicationName
    ** LPWSTR lpCommandLine command_line
    *  LPSECURITY_ATTRIBUTES lpProcessAttributes
    *  LPSECURITY_ATTRIBUTES lpThreadAttributes
    ** BOOL bInheritHandles inherit_handles
    *  DWORD dwCreationFlags
    *  LPVOID lpEnvironment
    ** LPWSTR lpCurrentDirectory current_directory
    *  LPSTARTUPINFO lpStartupInfo
    *  LPPROCESS_INFORMATION lpProcessInformation
    *  LPVOID lpUnknown2

Flags::

    creation_flags creation_flags

Ensure::

    lpProcessInformation

Pre::

    // Ensure the CREATE_SUSPENDED flag is set when calling
    // the original function.
    DWORD creation_flags = dwCreationFlags;
    dwCreationFlags |= CREATE_SUSPENDED;

    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpApplicationName, filepath);

Interesting::

    u filepath
    u command_line
    i inherit_handles
    i creation_flags
    u current_directory

Middle::

    int track = 0;

    if(ret != FALSE) {
        uint32_t mode = HOOK_MODE_ALL;

        const wchar_t *command_line = lpCommandLine;
        if(command_line == NULL) {
            command_line = lpApplicationName;
        }

        // Let's ask nicely whether we want to propagate execution into this
        // new process and if so, in what monitoring mode.
        if(monitor_mode_should_propagate(command_line, &mode) == 0) {
            pipe("PROCESS2:%d,%d,%d",
                lpProcessInformation->dwProcessId,
                lpProcessInformation->dwThreadId,
                mode);
            track = 1;
        }
    }

Logging::

    u filepath filepath
    u filepath_r lpApplicationName
    i creation_flags creation_flags
    i process_identifier lpProcessInformation->dwProcessId
    i thread_identifier lpProcessInformation->dwThreadId
    p process_handle lpProcessInformation->hProcess
    p thread_handle lpProcessInformation->hThread
    i track track

Post::

    if(ret != FALSE) {
        // If the CREATE_SUSPENDED flag was not set then we have to resume
        // the main thread ourselves.
        if((creation_flags & CREATE_SUSPENDED) == 0) {
            ResumeThread(lpProcessInformation->hThread);
        }

        sleep_skip_disable();
    }

    free_unicode_buffer(filepath);


CreateProcessWithLogonW
=======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpUsername
    ** LPCWSTR lpDomain
    ** LPCWSTR lpPassword
    ** DWORD dwLogonFlags
    ** LPCWSTR lpApplicationName
    ** LPWSTR lpCommandLine
    ** DWORD dwCreationFlags
    ** LPVOID lpEnvironment
    ** LPCWSTR lpCurrentDirectory
    ** LPSTARTUPINFOW lpStartupInfo
    ** LPPROCESS_INFORMATION lpProcessInformation

Middle::

    uint32_t pid = lpProcessInformation->dwProcessId;

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        pipe("PROCESS:%d", pid);
        sleep_skip_disable();
    }


CreateProcessWithTokenW
=======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** HANDLE hToken
    ** DWORD dwLogonFlags
    ** LPCWSTR lpApplicationName
    ** LPWSTR lpCommandLine
    ** DWORD dwCreationFlags
    ** LPVOID lpEnvironment
    ** LPCWSTR lpCurrentDirectory
    ** LPSTARTUPINFOW lpStartupInfo
    ** LPPROCESS_INFORMATION lpProcessInformation

Middle::

    uint32_t pid = lpProcessInformation->dwProcessId;

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        pipe("PROCESS:%d", pid);
        sleep_skip_disable();
    }


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

Middle::

    uint32_t pid = pid_from_process_handle(hProcess);

Post::

    pipe("PROCESS:%d", pid);
    sleep_skip_disable();


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

Middle::

    uint32_t pid = pid_from_process_handle(hProcess);

Post::

    pipe("PROCESS:%d", pid);
    sleep_skip_disable();


CreateThread
============

Signature::

    * Library: rtmpal
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpThreadAttributes
    ** SIZE_T dwStackSize
    ** LPTHREAD_START_ROUTINE lpStartAddress
    ** LPVOID lpParameter
    ** DWORD dwCreationFlags
    ** LPDWORD lpThreadId

Post::

    uint32_t pid = pid_from_thread_handle(ret);
    pipe("PROCESS:%d", pid);
    sleep_skip_disable();


CreateThreadpool
================

Signature::

    * Library: kernel32
    * Return value: PTP_POOL

Parameters::

    ** PVOID reserved


CreateThreadpoolCleanupGroup
============================

Signature::

    * Library: kernel32
    * Return value: PTP_CLEANUP_GROUP


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


CreateThreadpoolTimer
=====================

Signature::

    * Library: kernel32
    * Return value: PTP_TIMER

Parameters::

    ** PTP_TIMER_CALLBACK pfnti
    ** PVOID pv
    ** PTP_CALLBACK_ENVIRON pcbe


CreateThreadpoolWait
====================

Signature::

    * Library: kernel32
    * Return value: PTP_WAIT

Parameters::

    ** PTP_WAIT_CALLBACK pfnwa
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


DeleteFiber
===========

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPVOID lpFiber


DeleteProcThreadAttributeList
=============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList


DisassociateCurrentThreadFromCallback
=====================================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci


EmptyWorkingSet
===============

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess


EnumDeviceDrivers
=================

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** LPVOID *lpImageBase
    ** DWORD cb
    ** LPDWORD lpcbNeeded


EnumPageFilesA
==============

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** PENUM_PAGE_FILE_CALLBACKA pCallBackRoutine
    ** LPVOID pContext


EnumPageFilesW
==============

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** PENUM_PAGE_FILE_CALLBACKW pCallBackRoutine
    ** LPVOID pContext


EnumProcessModules
==================

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** HMODULE *lphModule
    ** DWORD cb
    ** LPDWORD lpcbNeeded


EnumProcessModulesEx
====================

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** HMODULE *lphModule
    ** DWORD cb
    ** LPDWORD lpcbNeeded
    ** DWORD dwFilterFlag


EnumProcesses
=============

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** DWORD *lpidProcess
    ** DWORD cb
    ** LPDWORD lpcbNeeded


ExitProcess
===========

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** UINT uExitCode


ExitThread
==========

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** DWORD dwExitCode


FlushProcessWriteBuffers
========================

Signature::

    * Library: kernel32
    * Return value: void


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


FreeLibraryWhenCallbackReturns
==============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** HMODULE mod


GetActiveProcessorCount
=======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** WORD GroupNumber


GetActiveProcessorGroupCount
============================

Signature::

    * Library: kernel32
    * Return value: WORD


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


GetCurrentProcess
=================

Signature::

    * Library: rtmpal
    * Return value: HANDLE


GetCurrentProcessId
===================

Signature::

    * Library: rtmpal
    * Return value: DWORD


GetCurrentThread
================

Signature::

    * Library: rtmpal
    * Return value: HANDLE


GetCurrentThreadId
==================

Signature::

    * Library: rtmpal
    * Return value: DWORD


GetDeviceDriverBaseNameA
========================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** LPVOID ImageBase
    ** LPSTR lpFilename
    ** DWORD nSize


GetDeviceDriverBaseNameW
========================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** LPVOID ImageBase
    ** LPWSTR lpBaseName
    ** DWORD nSize


GetDeviceDriverFileNameA
========================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** LPVOID ImageBase
    ** LPSTR lpFilename
    ** DWORD nSize


GetDeviceDriverFileNameW
========================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** LPVOID ImageBase
    ** LPWSTR lpFilename
    ** DWORD nSize


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


GetExitCodeProcess
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** LPDWORD lpExitCode


GetExitCodeThread
=================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** LPDWORD lpExitCode


GetGuiResources
===============

Signature::

    * Library: user32
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess
    ** DWORD uiFlags


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


GetMappedFileNameA
==================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess
    ** LPVOID lpv
    ** LPSTR lpFilename
    ** DWORD nSize


GetMappedFileNameW
==================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess
    ** LPVOID lpv
    ** LPWSTR lpFilename
    ** DWORD nSize


GetMaximumProcessorCount
========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** WORD GroupNumber


GetMaximumProcessorGroupCount
=============================

Signature::

    * Library: kernel32
    * Return value: WORD


GetModuleBaseNameA
==================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess
    ** HMODULE hModule
    ** LPSTR lpBaseName
    ** DWORD nSize


GetModuleBaseNameW
==================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess
    ** HMODULE hModule
    ** LPWSTR lpBaseName
    ** DWORD nSize


GetModuleInformation
====================

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** HMODULE hModule
    ** LPMODULEINFO lpmodinfo
    ** DWORD cb


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


GetNumaHighestNodeNumber
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PULONG HighestNodeNumber


GetNumaNodeNumberFromHandle
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** PUSHORT NodeNumber


GetNumaNodeProcessorMask
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UCHAR Node
    ** PULONGLONG ProcessorMask


GetNumaNodeProcessorMaskEx
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** USHORT Node
    ** PGROUP_AFFINITY ProcessorMask


GetNumaProcessorNode
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UCHAR Processor
    ** PUCHAR NodeNumber


GetNumaProcessorNodeEx
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PPROCESSOR_NUMBER Processor
    ** PUSHORT NodeNumber


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


GetPerformanceInfo
==================

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** PPERFORMANCE_INFORMATION pPerformanceInformation
    ** DWORD cb


GetPriorityClass
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess


GetProcessAffinityMask
======================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PDWORD_PTR lpProcessAffinityMask
    ** PDWORD_PTR lpSystemAffinityMask


GetProcessGroupAffinity
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PUSHORT GroupCount
    ** PUSHORT GroupArray


GetProcessHandleCount
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PDWORD pdwHandleCount


GetProcessId
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE Process


GetProcessIdOfThread
====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE Thread


GetProcessImageFileNameA
========================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess
    ** LPSTR lpImageFileName
    ** DWORD nSize


GetProcessImageFileNameW
========================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess
    ** LPWSTR lpImageFileName
    ** DWORD nSize


GetProcessIoCounters
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PIO_COUNTERS lpIoCounters


GetProcessMemoryInfo
====================

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE Process
    ** PPROCESS_MEMORY_COUNTERS ppsmemCounters
    ** DWORD cb


GetProcessMitigationPolicy
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PROCESS_MITIGATION_POLICY MitigationPolicy
    ** PVOID lpBuffer
    ** SIZE_T dwLength


GetProcessPriorityBoost
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PBOOL pDisablePriorityBoost


GetProcessShutdownParameters
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPDWORD lpdwLevel
    ** LPDWORD lpdwFlags


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


GetProcessVersion
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD ProcessId


GetProcessWorkingSetSize
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PSIZE_T lpMinimumWorkingSetSize
    ** PSIZE_T lpMaximumWorkingSetSize


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


GetProcessorSystemCycleTime
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** USHORT Group
    ** PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION Buffer
    ** PDWORD ReturnedLength


GetStartupInfoA
===============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSTARTUPINFOA lpStartupInfo


GetStartupInfoW
===============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSTARTUPINFOW lpStartupInfo


GetThreadGroupAffinity
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PGROUP_AFFINITY GroupAffinity


GetThreadIOPendingFlag
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PBOOL lpIOIsPending


GetThreadId
===========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE Thread


GetThreadIdealProcessorEx
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PPROCESSOR_NUMBER lpIdealProcessor


GetThreadInformation
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** THREAD_INFORMATION_CLASS ThreadInformationClass
    ** LPVOID ThreadInformation
    ** DWORD ThreadInformationSize


GetThreadPriority
=================

Signature::

    * Library: rtmpal
    * Return value: int

Parameters::

    ** HANDLE hThread


GetThreadPriorityBoost
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PBOOL pDisablePriorityBoost


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


GetWsChanges
============

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PPSAPI_WS_WATCH_INFORMATION lpWatchInfo
    ** DWORD cb


GetWsChangesEx
==============

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PPSAPI_WS_WATCH_INFORMATION_EX lpWatchInfoEx
    ** PDWORD cb


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


InitializeProcessForWsWatch
===========================

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess


IsImmersiveProcess
==================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess


IsProcessInJob
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE ProcessHandle
    ** HANDLE JobHandle
    ** PBOOL Result


IsThreadAFiber
==============

Signature::

    * Library: kernel32
    * Return value: BOOL


IsThreadpoolTimerSet
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_TIMER pti


IsWow64Message
==============

Signature::

    * Library: user32
    * Return value: BOOL


IsWow64Process
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PBOOL Wow64Process


LeaveCriticalSectionWhenCallbackReturns
=======================================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** PCRITICAL_SECTION pcs


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


OpenProcess
===========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** DWORD dwProcessId


OpenThread
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** DWORD dwThreadId


Process32First
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot
    ** LPPROCESSENTRY32 lppe


Process32FirstW
===============

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot
    ** LPPROCESSENTRY32W lppe


Process32Next
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot
    ** LPPROCESSENTRY32 lppe


Process32NextW
==============

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot
    ** LPPROCESSENTRY32W lppe


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


QueryProcessAffinityUpdateMode
==============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** LPDWORD lpdwFlags


QueryProcessCycleTime
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE ProcessHandle
    ** PULONG64 CycleTime


QueryThreadCycleTime
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE ThreadHandle
    ** PULONG64 CycleTime


QueryThreadpoolStackInformation
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_POOL ptpp
    ** PTP_POOL_STACK_INFORMATION ptpsi


QueryWorkingSet
===============

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PVOID pv
    ** DWORD cb


QueryWorkingSetEx
=================

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PVOID pv
    ** DWORD cb


QueueUserWorkItem
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPTHREAD_START_ROUTINE Function
    ** PVOID Context
    ** ULONG Flags


ReleaseMutexWhenCallbackReturns
===============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** HANDLE mut


ReleaseSemaphoreWhenCallbackReturns
===================================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** HANDLE sem
    ** DWORD crel


ResumeThread
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hThread

Pre::

    uint32_t pid = pid_from_thread_handle(hThread);
    if(pid != get_current_process_id()) {
        pipe("PROCESS:%d", pid);
        pipe("DUMPMEM:%d", pid);
    }

Post::

    if(NT_SUCCESS(ret) != FALSE) {
        sleep_skip_disable();
    }


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

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpName
    ** LPCWSTR lpValue


SetEventWhenCallbackReturns
===========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** HANDLE evt


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


SetPriorityClass
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** DWORD dwPriorityClass


SetProcessAffinityMask
======================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** DWORD_PTR dwProcessAffinityMask


SetProcessAffinityUpdateMode
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** DWORD dwFlags


SetProcessInformation
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PROCESS_INFORMATION_CLASS ProcessInformationClass
    ** LPVOID ProcessInformation
    ** DWORD ProcessInformationSize


SetProcessMitigationPolicy
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PROCESS_MITIGATION_POLICY MitigationPolicy
    ** PVOID lpBuffer
    ** SIZE_T dwLength


SetProcessPriorityBoost
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** BOOL bDisablePriorityBoost


SetProcessRestrictionExemption
==============================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** BOOL fEnableExemption


SetProcessShutdownParameters
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwLevel
    ** DWORD dwFlags


SetProcessWorkingSetSize
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** SIZE_T dwMinimumWorkingSetSize
    ** SIZE_T dwMaximumWorkingSetSize


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


SetThreadAffinityMask
=====================

Signature::

    * Library: rtmpal
    * Return value: DWORD_PTR

Parameters::

    ** HANDLE hThread
    ** DWORD_PTR dwThreadAffinityMask


SetThreadGroupAffinity
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** const GROUP_AFFINITY *GroupAffinity
    ** PGROUP_AFFINITY PreviousGroupAffinity


SetThreadIdealProcessor
=======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hThread
    ** DWORD dwIdealProcessor


SetThreadIdealProcessorEx
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PPROCESSOR_NUMBER lpIdealProcessor
    ** PPROCESSOR_NUMBER lpPreviousIdealProcessor


SetThreadInformation
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** THREAD_INFORMATION_CLASS ThreadInformationClass
    ** LPVOID ThreadInformation
    ** DWORD ThreadInformationSize


SetThreadPriority
=================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** int nPriority


SetThreadPriorityBoost
======================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** BOOL bDisablePriorityBoost


SetThreadStackGuarantee
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PULONG StackSizeInBytes


SetThreadpoolStackInformation
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_POOL ptpp
    ** PTP_POOL_STACK_INFORMATION ptpsi


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


SetThreadpoolTimerEx
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_TIMER pti
    ** PFILETIME pftDueTime
    ** DWORD msPeriod
    ** DWORD msWindowLength


SetThreadpoolWait
=================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WAIT pwa
    ** HANDLE h
    ** PFILETIME pftTimeout


SetThreadpoolWaitEx
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_WAIT pwa
    ** HANDLE h
    ** PFILETIME pftTimeout
    ** PVOID Reserved


Sleep
=====

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** DWORD dwMilliseconds


SleepEx
=======

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD dwMilliseconds
    ** BOOL bAlertable


StartThreadpoolIo
=================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_IO pio


SubmitThreadpoolWork
====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WORK pwk


SuspendThread
=============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hThread


SwitchToFiber
=============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPVOID lpFiber


SwitchToThread
==============

Signature::

    * Library: kernel32
    * Return value: BOOL


TerminateJobObject
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hJob
    ** UINT uExitCode


TerminateProcess
================

Signature::

    * Library: rtmpal
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** UINT uExitCode

Pre::

    uint32_t pid = pid_from_process_handle(hProcess);

    // If the process handle is a nullptr then it will kill all threads in
    // the current process except for the current one. TODO Should we have
    // any special handling for that? Perhaps the unhook detection logic?
    if(hProcess != NULL) {
        pipe("KILL:%d", pid);
    }


TerminateThread
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** DWORD dwExitCode


TrySubmitThreadpoolCallback
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_SIMPLE_CALLBACK pfns
    ** PVOID pv
    ** PTP_CALLBACK_ENVIRON pcbe


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


UserHandleGrantAccess
=====================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** HANDLE hUserHandle
    ** HANDLE hJob
    ** BOOL bGrant


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


WTSEnumerateProcessesA
======================

Signature::

    * Library: wtsapi32
    * Return value: BOOL

Parameters::

    ** HANDLE hServer
    ** DWORD Reserved
    ** DWORD Version
    ** PWTS_PROCESS_INFOA *ppProcessInfo
    ** DWORD *pCount


WTSEnumerateProcessesW
======================

Signature::

    * Library: wtsapi32
    * Return value: BOOL

Parameters::

    ** HANDLE hServer
    ** DWORD Reserved
    ** DWORD Version
    ** PWTS_PROCESS_INFOW *ppProcessInfo
    ** DWORD *pCount


WaitForInputIdle
================

Signature::

    * Library: user32
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess
    ** DWORD dwMilliseconds


WaitForThreadpoolIoCallbacks
============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_IO pio
    ** BOOL fCancelPendingCallbacks


WaitForThreadpoolTimerCallbacks
===============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_TIMER pti
    ** BOOL fCancelPendingCallbacks


WaitForThreadpoolWaitCallbacks
==============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WAIT pwa
    ** BOOL fCancelPendingCallbacks


WaitForThreadpoolWorkCallbacks
==============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WORK pwk
    ** BOOL fCancelPendingCallbacks


Wow64SuspendThread
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hThread


