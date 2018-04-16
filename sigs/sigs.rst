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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DisableThreadLibraryCalls
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hLibModule

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FreeLibrary
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HMODULE hLibModule

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FreeLibraryAndExitThread
========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** HMODULE hLibModule
    ** DWORD dwExitCode

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetDllDirectoryA
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPSTR lpBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetDllDirectoryW
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPWSTR lpBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetModuleFileNameA
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HMODULE hModule
    ** LPSTR lpFilename
    ** DWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetModuleFileNameW
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HMODULE hModule
    ** LPWSTR lpFilename
    ** DWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetModuleHandleA
================

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    ** LPCSTR lpModuleName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetModuleHandleW
================

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    ** LPCWSTR lpModuleName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetModuleHandleExA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** LPCSTR lpModuleName
    ** HMODULE *phModule

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetModuleHandleExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags
    ** LPCWSTR lpModuleName
    ** HMODULE *phModule

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcAddress
==============

Signature::

    * Library: kernel32
    * Return value: FARPROC

Parameters::

    ** HMODULE hModule
    ** LPCSTR lpProcName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


LoadLibraryA
============

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    ** LPCSTR lpLibFileName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


LoadLibraryW
============

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    ** LPCWSTR lpLibFileName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


LoadLibraryExA
==============

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    ** LPCSTR lpLibFileName
    ** HANDLE hFile
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


LoadLibraryExW
==============

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    ** LPCWSTR lpLibFileName
    ** HANDLE hFile
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


LoadPackagedLibrary
===================

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    ** LPCWSTR lpwLibFileName
    ** DWORD Reserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RemoveDllDirectory
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DLL_DIRECTORY_COOKIE Cookie

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetDefaultDllDirectories
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD DirectoryFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetDllDirectoryA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpPathName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetDllDirectoryW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpPathName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AddUsersToEncryptedFile
=======================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** PENCRYPTION_CERTIFICATE_LIST pEncryptionCertificates

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AreFileApisANSI
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CancelIo
========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CancelIoEx
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPOVERLAPPED lpOverlapped

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CancelSynchronousIo
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CloseEncryptedFileRaw
=====================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    ** PVOID pvContext

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpExistingFileName
    ** LPCWSTR lpNewFileName
    ** BOOL bFailIfExists

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpPathName
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateDirectoryW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpPathName
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateDirectoryExA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpTemplateDirectory
    ** LPCSTR lpNewDirectory
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateDirectoryExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpTemplateDirectory
    ** LPCWSTR lpNewDirectory
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateHardLinkA
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** LPCSTR lpExistingFileName
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateHardLinkW
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** LPCWSTR lpExistingFileName
    ** LPSECURITY_ATTRIBUTES lpSecurityAttributes

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateSymbolicLinkA
===================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    ** LPCSTR lpSymlinkFileName
    ** LPCSTR lpTargetFileName
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateSymbolicLinkW
===================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    ** LPCWSTR lpSymlinkFileName
    ** LPCWSTR lpTargetFileName
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DecryptFileA
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** DWORD dwReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DecryptFileW
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD dwReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DeleteFileA
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


EncryptFileA
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


EncryptFileW
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


EncryptionDisable
=================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCWSTR DirPath
    ** BOOL Disable

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FileEncryptionStatusA
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** LPDWORD lpStatus

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FileEncryptionStatusW
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** LPDWORD lpStatus

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindClose
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindFile

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindCloseChangeNotification
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hChangeHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindFirstChangeNotificationA
============================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCSTR lpPathName
    ** BOOL bWatchSubtree
    ** DWORD dwNotifyFilter

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindFirstChangeNotificationW
============================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpPathName
    ** BOOL bWatchSubtree
    ** DWORD dwNotifyFilter

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindFirstFileA
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCSTR lpFileName
    ** LPWIN32_FIND_DATAA lpFindFileData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindFirstFileW
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPCWSTR lpFileName
    ** LPWIN32_FIND_DATAW lpFindFileData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindNextChangeNotification
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hChangeHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindNextFileA
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindFile
    ** LPWIN32_FIND_DATAA lpFindFileData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindNextFileW
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindFile
    ** LPWIN32_FIND_DATAW lpFindFileData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindNextFileNameW
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindStream
    ** LPDWORD StringLength
    ** PWSTR LinkName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindNextStreamW
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFindStream
    ** LPVOID lpFindStreamData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FlushFileBuffers
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FreeEncryptionCertificateHashList
=================================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    ** PENCRYPTION_CERTIFICATE_HASH_LIST pUsers

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetBinaryTypeA
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpApplicationName
    ** LPDWORD lpBinaryType

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetBinaryTypeW
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpApplicationName
    ** LPDWORD lpBinaryType

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetCompressedFileSizeA
======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpFileName
    ** LPDWORD lpFileSizeHigh

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetCompressedFileSizeW
======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** LPDWORD lpFileSizeHigh

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetCompressedFileSizeTransactedA
================================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpFileName
    ** LPDWORD lpFileSizeHigh
    ** HANDLE hTransaction

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetCompressedFileSizeTransactedW
================================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** LPDWORD lpFileSizeHigh
    ** HANDLE hTransaction

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetCurrentDirectoryA
====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPSTR lpBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetCurrentDirectoryW
====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPWSTR lpBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetFileAttributesA
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpFileName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetFileAttributesW
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetFileAttributesExA
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** GET_FILEEX_INFO_LEVELS fInfoLevelId
    ** LPVOID lpFileInformation

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetFileAttributesExW
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** GET_FILEEX_INFO_LEVELS fInfoLevelId
    ** LPVOID lpFileInformation

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetFileInformationByHandle
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPBY_HANDLE_FILE_INFORMATION lpFileInformation

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetFileSize
===========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hFile
    ** LPDWORD lpFileSizeHigh

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetFileSizeEx
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** PLARGE_INTEGER lpFileSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetFileType
===========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hFile

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetLongPathNameA
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpszShortPath
    ** LPSTR lpszLongPath
    ** DWORD cchBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetLongPathNameW
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpszShortPath
    ** LPWSTR lpszLongPath
    ** DWORD cchBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetShortPathNameA
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpszLongPath
    ** LPSTR lpszShortPath
    ** DWORD cchBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetShortPathNameW
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpszLongPath
    ** LPWSTR lpszShortPath
    ** DWORD cchBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetTempPathA
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPSTR lpBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetTempPathW
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nBufferLength
    ** LPWSTR lpBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


MoveFileA
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpExistingFileName
    ** LPCSTR lpNewFileName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpExistingFileName
    ** LPCWSTR lpNewFileName
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenEncryptedFileRawW
=====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** ULONG ulFlags
    ** PVOID *pvContext

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenFile
========

Signature::

    * Library: kernel32
    * Return value: HFILE

Parameters::

    ** LPCSTR lpFileName
    ** LPOFSTRUCT lpReOpenBuff
    ** UINT uStyle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueryRecoveryAgentsOnEncryptedFile
==================================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** PENCRYPTION_CERTIFICATE_HASH_LIST *pRecoveryAgents

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueryUsersOnEncryptedFile
=========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** PENCRYPTION_CERTIFICATE_HASH_LIST *pUsers

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ReadEncryptedFileRaw
====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** PFE_EXPORT_FUNC pfExportCallback
    ** PVOID pvCallbackContext
    ** PVOID pvContext

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RemoveDirectoryA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpPathName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RemoveDirectoryW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpPathName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RemoveDirectoryTransactedA
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpPathName
    ** HANDLE hTransaction

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RemoveDirectoryTransactedW
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpPathName
    ** HANDLE hTransaction

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RemoveUsersFromEncryptedFile
============================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpFileName
    ** PENCRYPTION_CERTIFICATE_HASH_LIST pHashes

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetCurrentDirectoryA
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpPathName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetCurrentDirectoryW
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpPathName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetEndOfFile
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetFileApisToANSI
=================

Signature::

    * Library: kernel32
    * Return value: void

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetFileApisToOEM
================

Signature::

    * Library: kernel32
    * Return value: void

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetFileAttributesA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** DWORD dwFileAttributes

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetFileAttributesW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD dwFileAttributes

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetFileAttributesTransactedA
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpFileName
    ** DWORD dwFileAttributes
    ** HANDLE hTransaction

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetFileAttributesTransactedW
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpFileName
    ** DWORD dwFileAttributes
    ** HANDLE hTransaction

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetFileCompletionNotificationModes
==================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE FileHandle
    ** UCHAR Flags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetFileIoOverlappedRange
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE FileHandle
    ** PUCHAR OverlappedRangeStart
    ** ULONG Length

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetFileShortNameA
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPCSTR lpShortName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetFileShortNameW
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LPCWSTR lpShortName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetFileValidData
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** LONGLONG ValidDataLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetSearchPathMode
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD Flags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetUserFileEncryptionKey
========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** PENCRYPTION_CERTIFICATE pEncryptionCertificate

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


Wow64DisableWow64FsRedirection
==============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PVOID *OldValue

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


Wow64EnableWow64FsRedirection
=============================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    ** BOOLEAN Wow64FsEnableRedirection

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


Wow64RevertWow64FsRedirection
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PVOID OlValue

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WriteEncryptedFileRaw
=====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** PFE_IMPORT_FUNC pfImportCallback
    ** PVOID pvCallbackContext
    ** PVOID pvContext

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Post::

    wchar_t *filepath = get_unicode_buffer();

    if(NT_SUCCESS(ret) != FALSE &&
            path_get_full_path_handle(hFile, filepath) != 0) {
        pipe("FILE_NEW:%Z", filepath);
    }

    free_unicode_buffer(filepath);

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ChangeServiceConfig2A
=====================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwInfoLevel
    ** LPVOID lpInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ChangeServiceConfig2W
=====================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwInfoLevel
    ** LPVOID lpInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CloseServiceHandle
==================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hSCObject

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ControlService
==============

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwControl
    ** LPSERVICE_STATUS lpServiceStatus

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DeleteService
=============

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


NotifyBootConfigStatus
======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** BOOL BootAcceptable

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


NotifyServiceStatusChangeA
==========================

Signature::

    * Library: sechost
    * Return value: DWORD

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwNotifyMask
    ** PSERVICE_NOTIFYA pNotifyBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


NotifyServiceStatusChangeW
==========================

Signature::

    * Library: sechost
    * Return value: DWORD

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwNotifyMask
    ** PSERVICE_NOTIFYW pNotifyBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenSCManagerA
==============

Signature::

    * Library: sechost
    * Return value: SC_HANDLE

Parameters::

    ** LPCSTR lpMachineName
    ** LPCSTR lpDatabaseName
    ** DWORD dwDesiredAccess

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenSCManagerW
==============

Signature::

    * Library: sechost
    * Return value: SC_HANDLE

Parameters::

    ** LPCWSTR lpMachineName
    ** LPCWSTR lpDatabaseName
    ** DWORD dwDesiredAccess

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenServiceA
============

Signature::

    * Library: sechost
    * Return value: SC_HANDLE

Parameters::

    ** SC_HANDLE hSCManager
    ** LPCSTR lpServiceName
    ** DWORD dwDesiredAccess

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenServiceW
============

Signature::

    * Library: sechost
    * Return value: SC_HANDLE

Parameters::

    ** SC_HANDLE hSCManager
    ** LPCWSTR lpServiceName
    ** DWORD dwDesiredAccess

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueryServiceDynamicInformation
==============================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SERVICE_STATUS_HANDLE hServiceStatus
    ** DWORD dwInfoLevel
    ** PVOID *ppDynamicInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetServiceObjectSecurity
========================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** SECURITY_INFORMATION dwSecurityInformation
    ** PSECURITY_DESCRIPTOR lpSecurityDescriptor

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetServiceStatus
================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SERVICE_STATUS_HANDLE hServiceStatus
    ** LPSERVICE_STATUS lpServiceStatus

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


StartServiceA
=============

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwNumServiceArgs
    ** LPCSTR *lpServiceArgVectors

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


StartServiceW
=============

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hService
    ** DWORD dwNumServiceArgs
    ** LPCWSTR *lpServiceArgVectors

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


StartServiceCtrlDispatcherA
===========================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** const SERVICE_TABLE_ENTRYA *lpServiceStartTable

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


StartServiceCtrlDispatcherW
===========================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    ** const SERVICE_TABLE_ENTRYW *lpServiceStartTable

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CeipIsOptedIn
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DnsHostnameToComputerNameA
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR Hostname
    ** LPSTR ComputerName
    ** LPDWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DnsHostnameToComputerNameW
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR Hostname
    ** LPWSTR ComputerName
    ** LPDWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


EnumSystemFirmwareTables
========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** DWORD FirmwareTableProviderSignature
    ** PVOID pFirmwareTableEnumBuffer
    ** DWORD BufferSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ExpandEnvironmentStringsA
=========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpSrc
    ** LPSTR lpDst
    ** DWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ExpandEnvironmentStringsW
=========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpSrc
    ** LPWSTR lpDst
    ** DWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetComputerNameA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPSTR lpBuffer
    ** LPDWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetComputerNameW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPWSTR lpBuffer
    ** LPDWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetComputerNameExA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** COMPUTER_NAME_FORMAT NameType
    ** LPSTR lpBuffer
    ** LPDWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetComputerNameExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** COMPUTER_NAME_FORMAT NameType
    ** LPWSTR lpBuffer
    ** LPDWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetCurrentHwProfileA
====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPHW_PROFILE_INFOA lpHwProfileInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetCurrentHwProfileW
====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPHW_PROFILE_INFOW lpHwProfileInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetFirmwareType
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PFIRMWARE_TYPE FirmwareType

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetNativeSystemInfo
===================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSYSTEM_INFO lpSystemInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetSystemDirectoryA
===================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPSTR lpBuffer
    ** UINT uSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetSystemDirectoryW
===================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPWSTR lpBuffer
    ** UINT uSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetSystemInfo
=============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSYSTEM_INFO lpSystemInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetSystemRegistryQuota
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PDWORD pdwQuotaAllowed
    ** PDWORD pdwQuotaUsed

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetSystemWindowsDirectoryA
==========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPSTR lpBuffer
    ** UINT uSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetSystemWindowsDirectoryW
==========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPWSTR lpBuffer
    ** UINT uSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetSystemWow64DirectoryA
========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPSTR lpBuffer
    ** UINT uSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetSystemWow64DirectoryW
========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPWSTR lpBuffer
    ** UINT uSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetUserNameA
============

Signature::

    * Interesting: yes
    * Library: advapi32
    * Return value: BOOL

Parameters::

    *  LPCSTR lpBuffer
    *  LPDWORD lpnSize

Ensure::

    lpnSize

Logging::

    S username copy_uint32(lpnSize)-1, lpBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetUserNameW
============

Signature::

    * Interesting: yes
    * Library: advapi32
    * Return value: BOOL

Parameters::

    *  LPWSTR lpBuffer
    *  LPDWORD lpnSize

Ensure::

    lpnSize

Logging::

    U username copy_uint32(lpnSize)-1, lpBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetUserNameExA
==============

Signature::

    * Interesting: yes
    * Library: secur32
    * Return value: BOOL

Parameters::

    ** EXTENDED_NAME_FORMAT NameFormat name_format
    *  LPCSTR lpNameBuffer
    *  PULONG lpnSize

Ensure::

    lpnSize

Logging::

    S username copy_uint32(lpnSize)-1, lpNameBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetUserNameExW
==============

Signature::

    * Interesting: yes
    * Library: secur32
    * Return value: BOOL

Parameters::

    ** EXTENDED_NAME_FORMAT NameFormat name_format
    *  LPWSTR lpNameBuffer
    *  PULONG lpnSize

Ensure::

    lpnSize

Logging::

    U username copy_uint32(lpnSize)-1, lpNameBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetVersion
==========

Signature::

    * Library: kernel32
    * Return value: DWORD

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetVersionExA
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPOSVERSIONINFOA lpVersionInformation

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetVersionExW
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPOSVERSIONINFOW lpVersionInformation

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetWindowsDirectoryA
====================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPSTR lpBuffer
    ** UINT uSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetWindowsDirectoryW
====================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** LPWSTR lpBuffer
    ** UINT uSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


IsNativeVhdBoot
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PBOOL NativeVhdBoot

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


IsProcessorFeaturePresent
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD ProcessorFeature

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueryPerformanceCounter
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LARGE_INTEGER *lpPerformanceCount

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueryPerformanceFrequency
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LARGE_INTEGER *lpFrequency

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetComputerNameA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR lpComputerName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetComputerNameW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpComputerName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetComputerNameExA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** COMPUTER_NAME_FORMAT NameType
    ** LPCSTR lpBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetComputerNameExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** COMPUTER_NAME_FORMAT NameType
    ** LPCWSTR lpBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


VerSetConditionMask
===================

Signature::

    * Library: kernel32
    * Return value: ULONGLONG

Parameters::

    ** ULONGLONG ConditionMask
    ** ULONG TypeMask
    ** UCHAR Condition

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


VerifyVersionInfoA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPOSVERSIONINFOEXA lpVersionInformation
    ** DWORD dwTypeMask
    ** DWORDLONG dwlConditionMask

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


VerifyVersionInfoW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPOSVERSIONINFOEXW lpVersionInformation
    ** DWORD dwTypeMask
    ** DWORDLONG dwlConditionMask

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CloseHandle
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hObject

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetHandleInformation
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hObject
    ** LPDWORD lpdwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetHandleInformation
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hObject
    ** DWORD dwMask
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegCloseKey
===========

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegConnectRegistryA
===================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** LPCSTR lpMachineName
    ** HKEY hKey
    ** PHKEY phkResult

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegConnectRegistryW
===================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** LPCWSTR lpMachineName
    ** HKEY hKey
    ** PHKEY phkResult

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegCopyTreeA
============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKeySrc
    ** LPCSTR lpSubKey
    ** HKEY hKeyDest

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegCopyTreeW
============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKeySrc
    ** LPCWSTR lpSubKey
    ** HKEY hKeyDest

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegCreateKeyA
=============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** PHKEY phkResult

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegCreateKeyW
=============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** PHKEY phkResult

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegCreateKeyExA
===============

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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegCreateKeyExW
===============

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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegDeleteKeyA
=============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegDeleteKeyW
=============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegDeleteKeyValueA
==================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** LPCSTR lpValueName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegDeleteKeyValueW
==================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** LPCWSTR lpValueName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegDeleteTreeA
==============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegDeleteTreeW
==============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegDeleteValueA
===============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpValueName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegDeleteValueW
===============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpValueName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegDisablePredefinedCache
=========================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegDisablePredefinedCacheEx
===========================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegDisableReflectionKey
=======================

Signature::

    * Library: advapi32
    * Return value: LONG

Parameters::

    ** HKEY hBase

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegEnableReflectionKey
======================

Signature::

    * Library: advapi32
    * Return value: LONG

Parameters::

    ** HKEY hBase

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegEnumKeyExA
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** DWORD dwIndex
    ** LPSTR lpName
    ** LPDWORD lpcchName
    ** LPDWORD lpReserved
    ** LPSTR lpClass
    ** LPDWORD lpcchClass
    ** PFILETIME lpftLastWriteTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegEnumKeyExW
=============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** DWORD dwIndex
    ** LPWSTR lpName
    ** LPDWORD lpcchName
    ** LPDWORD lpReserved
    ** LPWSTR lpClass
    ** LPDWORD lpcchClass
    ** PFILETIME lpftLastWriteTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegFlushKey
===========

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegLoadKeyA
===========

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** LPCSTR lpFile

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegLoadKeyW
===========

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** LPCWSTR lpFile

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegLoadMUIStringA
=================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR pszValue
    ** LPSTR pszOutBuf
    ** DWORD cbOutBuf
    ** LPDWORD pcbData
    ** DWORD Flags
    ** LPCSTR pszDirectory

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegLoadMUIStringW
=================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR pszValue
    ** LPWSTR pszOutBuf
    ** DWORD cbOutBuf
    ** LPDWORD pcbData
    ** DWORD Flags
    ** LPCWSTR pszDirectory

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegOpenCurrentUser
==================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** REGSAM samDesired
    ** PHKEY phkResult

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegOpenKeyA
===========

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** PHKEY phkResult

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegOpenKeyW
===========

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** PHKEY phkResult

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegOpenKeyExA
=============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** DWORD ulOptions
    ** REGSAM samDesired
    ** PHKEY phkResult

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegOpenKeyExW
=============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** DWORD ulOptions
    ** REGSAM samDesired
    ** PHKEY phkResult

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegOverridePredefKey
====================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** HKEY hNewHKey

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegQueryInfoKeyA
================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPSTR lpClass
    ** LPDWORD lpcchClass
    ** LPDWORD lpReserved
    ** LPDWORD lpcSubKeys
    ** LPDWORD lpcbMaxSubKeyLen
    ** LPDWORD lpcbMaxClassLen
    ** LPDWORD lpcValues
    ** LPDWORD lpcbMaxValueNameLen
    ** LPDWORD lpcbMaxValueLen
    ** LPDWORD lpcbSecurityDescriptor
    ** PFILETIME lpftLastWriteTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegQueryInfoKeyW
================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPWSTR lpClass
    ** LPDWORD lpcchClass
    ** LPDWORD lpReserved
    ** LPDWORD lpcSubKeys
    ** LPDWORD lpcbMaxSubKeyLen
    ** LPDWORD lpcbMaxClassLen
    ** LPDWORD lpcValues
    ** LPDWORD lpcbMaxValueNameLen
    ** LPDWORD lpcbMaxValueLen
    ** LPDWORD lpcbSecurityDescriptor
    ** PFILETIME lpftLastWriteTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegQueryReflectionKey
=====================

Signature::

    * Library: advapi32
    * Return value: LONG

Parameters::

    ** HKEY hBase
    ** BOOL *bIsReflectionDisabled

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegQueryValueA
==============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey
    ** LPSTR lpData
    ** PLONG lpcbData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegQueryValueW
==============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey
    ** LPWSTR lpData
    ** PLONG lpcbData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegQueryValueExA
================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpValueName
    ** LPDWORD lpReserved
    ** LPDWORD lpType
    ** LPBYTE lpData
    ** LPDWORD lpcbData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegQueryValueExW
================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpValueName
    ** LPDWORD lpReserved
    ** LPDWORD lpType
    ** LPBYTE lpData
    ** LPDWORD lpcbData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegRestoreKeyA
==============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpFile
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegRestoreKeyW
==============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpFile
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegSaveKeyA
===========

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpFile
    ** const LPSECURITY_ATTRIBUTES lpSecurityAttributes

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegSaveKeyW
===========

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpFile
    ** const LPSECURITY_ATTRIBUTES lpSecurityAttributes

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegSetKeySecurity
=================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** SECURITY_INFORMATION SecurityInformation
    ** PSECURITY_DESCRIPTOR pSecurityDescriptor

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegSetValueExA
==============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpValueName
    ** DWORD Reserved
    ** DWORD dwType
    ** const BYTE *lpData
    ** DWORD cbData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegSetValueExW
==============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpValueName
    ** DWORD Reserved
    ** DWORD dwType
    ** const BYTE *lpData
    ** DWORD cbData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegUnLoadKeyA
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCSTR lpSubKey

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegUnLoadKeyW
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** LPCWSTR lpSubKey

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ActiveXObjectFncObj_Construct
=============================

Signature::

    * Library: jscript
    * Return value: HRESULT

Parameters::

    *  void *this
    *  VAR *unk1
    *  int unk2
    *  VAR *args

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    wchar_t *objname = NULL; void *session = ((void **) this)[3];

    VAR *value = iexplore_var_getvalue(args, session);
    if(value != NULL) {
        objname = *((wchar_t **) value + 1);
    }

Logging::

    u objname objname


CDocument_write
===============

Signature::

    * Is success: 1
    * Library: mshtml
    * Return value: int

Parameters::

    *  void *cdocument
    *  SAFEARRAY *arr

Middle::

    bson b; char index[8];
    bson_init_size(&b, mem_suggested_size(4096));
    bson_append_start_array(&b, "lines");

    VARIANT *elements = (VARIANT *) arr->pvData;
    for (uint32_t idx = 0, jdx = 0; idx < arr->rgsabound[0].cElements;
            idx++, elements++) {
        if(elements->vt == VT_BSTR && elements->bstrVal != NULL) {
            our_snprintf(index, sizeof(index), "%d", jdx++);
            log_wstring(&b, index, elements->bstrVal,
                sys_string_length(elements->bstrVal));
        }
    }

    bson_append_finish_array(&b);
    bson_finish(&b);

Logging::

    z lines &b

Post::

    bson_destroy(&b);

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CElement_put_innerHTML
======================

Signature::

    * Library: mshtml
    * Return value: HRESULT

Parameters::

    *  void *celement
    ** const wchar_t *html

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CHyperlink_SetUrlComponent
==========================

Signature::

    * Is success: 1
    * Library: mshtml
    * Return value: int

Parameters::

    *  void *chyperlink
    ** const wchar_t *component
    ** int index

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CIFrameElement_CreateElement
============================

Signature::

    * Library: mshtml
    * Return value: HRESULT

Parameters::

    *  void *chtmtag
    *  void *cdoc
    *  void **celement

Middle::

    bson b;
    bson_init_size(&b, mem_suggested_size(1024));
    bson_append_start_object(&b, "attributes");

    chtmtag_attrs(chtmtag, &b);

    bson_append_finish_object(&b);
    bson_finish(&b);

Logging::

    z attributes &b

Post::

    bson_destroy(&b);

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CImgElement_put_src
===================

Signature::

    * Library: mshtml
    * Return value: HRESULT

Parameters::

    *  void *celement
    ** const wchar_t *src

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


COleScript_Compile
==================

Signature::

    * Is success: ret >= 0
    * Library: jscript
    * Return value: int

Parameters::

    *  void *this
    *  void *script_body
    ** const wchar_t *script
    *  uintptr_t unk1
    *  uintptr_t unk2
    *  uintptr_t unk3
    ** const wchar_t *type
    *  void *exception

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CScriptElement_put_src
======================

Signature::

    * Library: mshtml
    * Return value: HRESULT

Parameters::

    *  void *cscriptelement
    ** const wchar_t *url

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CWindow_AddTimeoutCode
======================

Signature::

    * Library: mshtml
    * Return value: HRESULT

Parameters::

    *  void *cwindow
    *  VARIANT *data
    ** const wchar_t *argument
    ** int milliseconds
    *  int repeat
    *  void *unk2

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    wchar_t *code = NULL;
    if(data != NULL && data->vt == VT_BSTR) {
        code = data->bstrVal;
    }

    VARIANT v; v.vt = VT_EMPTY;
    if(data != NULL && data->vt == VT_DISPATCH) {
        if(SUCCEEDED(variant_change_type(&v, data, 0, VT_BSTR)) != FALSE) {
            code = v.bstrVal;
        }
    }

Logging::

    u code code
    i repeat repeat != 0

Post::

    if(v.vt != VT_EMPTY) {
        variant_clear(&v);
    }


CertControlStore
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    ** HCERTSTORE hCertStore
    ** DWORD dwFlags
    ** DWORD dwCtrlType
    ** void *pvCtrlPara

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CertCreateCertificateContext
============================

Signature::

    * Library: crypt32
    * Return value: PCCERT_CONTEXT

Parameters::

    ** DWORD dwCertEncodingType
    ** const BYTE *pbCertEncoded
    ** DWORD cbCertEncoded

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CertOpenStore
=============

Signature::

    * Library: crypt32
    * Return value: HCERTSTORE

Parameters::

    ** LPCSTR lpszStoreProvider
    ** DWORD dwEncodingType
    ** HCRYPTPROV_LEGACY hCryptProv
    ** DWORD dwFlags
    ** const void *pvPara

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CertOpenSystemStoreA
====================

Signature::

    * Library: crypt32
    * Return value: HCERTSTORE

Parameters::

    ** HCRYPTPROV_LEGACY hProv
    ** LPCSTR szSubsystemProtocol

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CertOpenSystemStoreW
====================

Signature::

    * Library: crypt32
    * Return value: HCERTSTORE

Parameters::

    ** HCRYPTPROV_LEGACY hProv
    ** LPCWSTR szSubsystemProtocol

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CoCreateInstance
================

Signature::

    * Library: ole32
    * Mode: exploit
    * Return value: HRESULT

Parameters::

    ** REFCLSID rclsid clsid
    *  LPUNKNOWN pUnkOuter
    ** DWORD dwClsContext class_context
    ** REFIID riid iid
    *  LPVOID *ppv

Interesting::

    b sizeof(CLSID), rclsid
    i class_context
    b sizeof(IID), riid

Post::

    ole_enable_hooks(rclsid);

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CoCreateInstanceEx
==================

Signature::

    * Library: ole32
    * Mode: exploit
    * Return value: HRESULT

Parameters::

    ** REFCLSID rclsid clsid
    *  IUnknown *punkOuter
    ** DWORD dwClsCtx class_context
    *  COSERVERINFO *pServerInfo
    *  DWORD dwCount
    *  MULTI_QI *pResults

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    bson b; char index[8], clsid[64];
    bson_init(&b);

    bson_append_start_array(&b, "iid");

    MULTI_QI *multi_qi = pResults;
    for (uint32_t idx = 0; idx < dwCount; idx++, multi_qi++) {
        our_snprintf(index, sizeof(index), "%d", idx++);
        clsid_to_string(copy_ptr(&multi_qi->pIID), clsid);
        log_string(&b, index, clsid, our_strlen(clsid));
    }

    bson_append_finish_array(&b);
    bson_finish(&b);

Logging::

    z iid &b

Post::

    ole_enable_hooks(rclsid);
    bson_destroy(&b);


CoGetClassObject
================

Signature::

    * Library: ole32
    * Mode: exploit
    * Return value: HRESULT

Parameters::

    ** REFCLSID rclsid clsid
    ** DWORD dwClsContext class_context
    *  COSERVERINFO *pServerInfo
    ** REFIID riid iid
    *  LPVOID *ppv

Post::

    ole_enable_hooks(rclsid);

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CoInitializeEx
==============

Signature::

    * Library: ole32
    * Mode: exploit
    * Return value: HRESULT

Parameters::

    *  LPVOID pvReserved
    ** DWORD dwCoInit options

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CoInitializeSecurity
====================

Signature::

    * Library: ole32
    * Mode: exploit
    * Return value: HRESULT

Parameters::

    *  PSECURITY_DESCRIPTOR pSecDesc
    *  LONG cAuthSvc
    *  SOLE_AUTHENTICATION_SERVICE *asAuthSvc
    *  void *pReserved1
    *  DWORD dwAuthnLevel
    *  DWORD dwImpLevel
    *  void *pAuthList
    *  DWORD dwCapabilities
    *  void *pReserved3

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ConnectEx
=========

Signature::

    * Library: ws2_32
    * Prune: resolve
    * Return value: BOOL

Parameters::

    ** SOCKET s socket
    *  const struct sockaddr *name
    *  int namelen
    *  PVOID lpSendBuffer
    *  DWORD dwSendDataLength
    *  LPDWORD lpdwBytesSent
    *  LPOVERLAPPED lpOverlapped

Ensure::

    lpdwBytesSent

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    const char *ip = NULL; int port = 0;
    get_ip_port(name, &ip, &port);

Logging::

    s ip_address ip
    i port port
    b buffer (uintptr_t) *lpdwBytesSent, lpSendBuffer


CreateActCtxW
=============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** PCACTCTXW pActCtx

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateToolhelp32Snapshot
========================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwFlags
    ** DWORD th32ProcessID

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptAcquireContextA
====================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    ** HCRYPTPROV *phProv
    ** LPCSTR szContainer
    ** LPCSTR szProvider
    ** DWORD dwProvType
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptAcquireContextW
====================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    ** HCRYPTPROV *phProv
    ** LPCWSTR szContainer
    ** LPCWSTR szProvider
    ** DWORD dwProvType
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptCreateHash
===============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    ** HCRYPTPROV hProv
    ** ALG_ID Algid
    ** HCRYPTKEY hKey
    ** DWORD dwFlags
    ** HCRYPTHASH *phHash

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptDecodeMessage
==================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    ** DWORD dwMsgTypeFlags
    ** PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara
    ** PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara
    ** DWORD dwSignerIndex
    ** const BYTE *pbEncodedBlob
    ** DWORD cbEncodedBlob
    ** DWORD dwPrevInnerContentType
    ** DWORD *pdwMsgType
    ** DWORD *pdwInnerContentType
    ** BYTE *pbDecoded
    ** DWORD *pcbDecoded
    ** PCCERT_CONTEXT *ppXchgCert
    ** PCCERT_CONTEXT *ppSignerCert

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptDecodeObjectEx
===================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    ** DWORD dwCertEncodingType
    ** LPCSTR lpszStructType
    ** const BYTE *pbEncoded
    ** DWORD cbEncoded
    ** DWORD dwFlags
    ** PCRYPT_DECODE_PARA pDecodePara
    ** void *pvStructInfo
    ** DWORD *pcbStructInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptDecrypt
============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    ** HCRYPTKEY hKey
    ** HCRYPTHASH hHash
    ** BOOL Final
    ** DWORD dwFlags
    ** BYTE *pbData
    ** DWORD *pdwDataLen

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptDecryptMessage
===================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    ** PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara
    ** const BYTE *pbEncryptedBlob
    ** DWORD cbEncryptedBlob
    ** BYTE *pbDecrypted
    ** DWORD *pcbDecrypted
    ** PCCERT_CONTEXT *ppXchgCert

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptEncrypt
============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    ** HCRYPTKEY hKey
    ** HCRYPTHASH hHash
    ** BOOL Final
    ** DWORD dwFlags
    ** BYTE *pbData
    ** DWORD *pdwDataLen
    ** DWORD dwBufLen

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptEncryptMessage
===================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    ** PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara
    ** DWORD cRecipientCert
    ** PCCERT_CONTEXT rgpRecipientCert[]
    ** const BYTE *pbToBeEncrypted
    ** DWORD cbToBeEncrypted
    ** BYTE *pbEncryptedBlob
    ** DWORD *pcbEncryptedBlob

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptExportKey
==============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    ** HCRYPTKEY hKey
    ** HCRYPTKEY hExpKey
    ** DWORD dwBlobType
    ** DWORD dwFlags
    ** BYTE *pbData
    ** DWORD *pdwDataLen

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptGenKey
===========

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    ** HCRYPTPROV hProv
    ** ALG_ID Algid
    ** DWORD dwFlags
    ** HCRYPTKEY *phKey

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptHashData
=============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    ** HCRYPTHASH hHash
    ** const BYTE *pbData
    ** DWORD dwDataLen
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptHashMessage
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    ** PCRYPT_HASH_MESSAGE_PARA pHashPara
    ** BOOL fDetachedHash
    ** DWORD cToBeHashed
    ** const BYTE *rgpbToBeHashed[]
    ** DWORD rgcbToBeHashed[]
    ** BYTE *pbHashedBlob
    ** DWORD *pcbHashedBlob
    ** BYTE *pbComputedHash
    ** DWORD *pcbComputedHash

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptProtectData
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    ** DATA_BLOB *pDataIn
    ** LPCWSTR szDataDescr
    ** DATA_BLOB *pOptionalEntropy
    ** PVOID pvReserved
    ** CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct
    ** DWORD dwFlags
    ** DATA_BLOB *pDataOut

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptProtectMemory
==================

Signature::

    * Library: dpapi
    * Return value: BOOL

Parameters::

    ** LPVOID pDataIn
    ** DWORD cbDataIn
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptUnprotectData
==================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    ** DATA_BLOB *pDataIn
    ** LPWSTR *ppszDataDescr
    ** DATA_BLOB *pOptionalEntropy
    ** PVOID pvReserved
    ** CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct
    ** DWORD dwFlags
    ** DATA_BLOB *pDataOut

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CryptUnprotectMemory
====================

Signature::

    * Library: dpapi
    * Return value: BOOL

Parameters::

    ** LPVOID pDataIn
    ** DWORD cbDataIn
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DecryptMessage
==============

Signature::

    * Library: secur32
    * Return value: SECURITY_STATUS

Parameters::

    ** PCtxtHandle phContext context_handle
    *  PSecBufferDesc pMessage
    ** ULONG MessageSeqNo number
    ** PULONG pfQOP qop

Middle::

    uint8_t *buf = NULL; uintptr_t length = 0;

    if(pMessage != NULL && pMessage->pBuffers != NULL) {
        secbuf_get_buffer(pMessage->cBuffers,
            pMessage->pBuffers, &buf, &length);
    }

Logging::

    !b buffer length, buf

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DeleteUrlCacheEntryA
====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrlName url

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DeleteUrlCacheEntryW
====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPWSTR lpszUrlName url

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DnsQuery_A
==========

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    ** PCSTR pszName
    ** WORD wType
    ** DWORD Options
    ** PVOID pExtra
    ** PDNS_RECORD *ppQueryResults
    ** PVOID *pReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DnsQuery_UTF8
=============

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    ** PCSTR pszName
    ** WORD wType
    ** DWORD Options
    ** PVOID pExtra
    ** PDNS_RECORD *ppQueryResults
    ** PVOID *pReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DnsQuery_W
==========

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    ** PCWSTR pszName
    ** WORD wType
    ** DWORD Options
    ** PVOID pExtra
    ** PDNS_RECORD *ppQueryResults
    ** PVOID *pReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DrawTextExA
===========

Signature::

    * Library: user32
    * Return value: int

Parameters::

    ** HDC hdc
    ** LPSTR lpchText
    ** int cchText
    ** LPRECT lprc
    ** UINT format
    ** LPDRAWTEXTPARAMS lpdtp

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DrawTextExW
===========

Signature::

    * Library: user32
    * Return value: int

Parameters::

    ** HDC hdc
    ** LPWSTR lpchText
    ** int cchText
    ** LPRECT lprc
    ** UINT format
    ** LPDRAWTEXTPARAMS lpdtp

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


EncryptMessage
==============

Signature::

    * Library: secur32
    * Return value: SECURITY_STATUS

Parameters::

    ** PCtxtHandle phContext context_handle
    ** ULONG fQOP qop
    *  PSecBufferDesc pMessage
    ** ULONG MessageSeqNo number

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    uint8_t *buf = NULL; uintptr_t length = 0;

    if(pMessage != NULL && pMessage->pBuffers != NULL) {
        secbuf_get_buffer(pMessage->cBuffers,
            pMessage->pBuffers, &buf, &length);
        buf = memdup(buf, length);
    }

Logging::

    !b buffer length, buf

Post::

    mem_free(buf);


EnumServicesStatusA
===================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hSCManager
    ** DWORD dwServiceType
    ** DWORD dwServiceState
    ** LPENUM_SERVICE_STATUSA lpServices
    ** DWORD cbBufSize
    ** LPDWORD pcbBytesNeeded
    ** LPDWORD lpServicesReturned
    ** LPDWORD lpResumeHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


EnumServicesStatusW
===================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** SC_HANDLE hSCManager
    ** DWORD dwServiceType
    ** DWORD dwServiceState
    ** LPENUM_SERVICE_STATUSW lpServices
    ** DWORD cbBufSize
    ** LPDWORD pcbBytesNeeded
    ** LPDWORD lpServicesReturned
    ** LPDWORD lpResumeHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


EnumWindows
===========

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** WNDENUMPROC lpEnumFunc
    ** LPARAM lParam

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ExitWindowsEx
=============

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** UINT uFlags
    ** DWORD dwReason

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindResourceA
=============

Signature::

    * Library: kernel32
    * Return value: HRSRC

Parameters::

    ** HMODULE hModule
    *  LPCSTR lpName
    *  LPCSTR lpType

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    char value[10], value2[10], *name, *type;

    int_or_strA(&name, lpName, value);
    int_or_strA(&type, lpType, value2);

Logging::

    s name name
    s type type


FindResourceExA
===============

Signature::

    * Library: kernel32
    * Return value: HRSRC

Parameters::

    ** HMODULE hModule
    *  LPCSTR lpType
    *  LPCSTR lpName
    ** WORD wLanguage

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    char value[10], value2[10], *name, *type;

    int_or_strA(&name, lpName, value);
    int_or_strA(&type, lpType, value2);

Logging::

    s name name
    s type type


FindResourceExW
===============

Signature::

    * Library: kernel32
    * Return value: HRSRC

Parameters::

    ** HMODULE hModule
    *  LPCWSTR lpType
    *  LPCWSTR lpName
    ** WORD wLanguage

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    wchar_t value[10], value2[10], *name, *type;

    int_or_strW(&name, lpName, value);
    int_or_strW(&type, lpType, value2);

Logging::

    u name name
    u type type


FindResourceW
=============

Signature::

    * Library: kernel32
    * Return value: HRSRC

Parameters::

    ** HMODULE hModule
    *  LPCWSTR lpName
    *  LPCWSTR lpType

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    wchar_t value[10], value2[10], *name, *type;

    int_or_strW(&name, lpName, value);
    int_or_strW(&type, lpType, value2);

Logging::

    u name name
    u type type


FindWindowA
===========

Signature::

    * Library: user32
    * Return value: HWND

Parameters::

    ** LPCSTR lpClassName
    ** LPCSTR lpWindowName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindWindowExA
=============

Signature::

    * Library: user32
    * Return value: HWND

Parameters::

    ** HWND hWndParent
    ** HWND hWndChildAfter
    ** LPCSTR lpszClass
    ** LPCSTR lpszWindow

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindWindowExW
=============

Signature::

    * Library: user32
    * Return value: HWND

Parameters::

    ** HWND hWndParent
    ** HWND hWndChildAfter
    ** LPCWSTR lpszClass
    ** LPCWSTR lpszWindow

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindWindowW
===========

Signature::

    * Library: user32
    * Return value: HWND

Parameters::

    ** LPCWSTR lpClassName
    ** LPCWSTR lpWindowName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetAdaptersAddresses
====================

Signature::

    * Is success: ret == ERROR_SUCCESS
    * Library: iphlpapi
    * Return value: ULONG

Parameters::

    ** ULONG Family family
    ** ULONG Flags flags
    *  PVOID Reserved
    *  PIP_ADAPTER_ADDRESSES AdapterAddresses
    *  PULONG SizePointer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetAdaptersInfo
===============

Signature::

    * Is success: ret == NO_ERROR
    * Library: iphlpapi
    * Return value: DWORD

Parameters::

    *  PIP_ADAPTER_INFO pAdapterInfo
    *  PULONG pOutBufLen

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetAsyncKeyState
================

Signature::

    * Library: user32
    * Return value: SHORT

Parameters::

    ** int vKey

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetBestInterfaceEx
==================

Signature::

    * Is success: ret == NO_ERROR
    * Library: iphlpapi
    * Return value: DWORD

Parameters::

    *  struct sockaddr *pDestAddr
    *  PDWORD pdwBestIfIndex

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetCursorPos
============

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** LPPOINT lpPoint

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetFileVersionInfoExW
=====================

Signature::

    * Library: version
    * Prune: resolve
    * Return value: BOOL

Parameters::

    ** DWORD dwFlags flags
    ** LPCWSTR lptstrFilename filepath
    *  DWORD dwHandle
    *  DWORD dwLen
    *  LPVOID lpData

Logging::

    b buffer dwLen, lpData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetFileVersionInfoSizeExW
=========================

Signature::

    * Is success: ret != 0
    * Library: version
    * Prune: resolve
    * Return value: DWORD

Parameters::

    ** DWORD dwFlags flags
    ** LPCWSTR lptstrFilename filepath
    *  LPDWORD lpdwHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetFileVersionInfoSizeW
=======================

Signature::

    * Is success: ret != 0
    * Library: version
    * Return value: DWORD

Parameters::

    ** LPCWSTR lptstrFilename filepath
    *  LPDWORD lpdwHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetFileVersionInfoW
===================

Signature::

    * Library: version
    * Return value: BOOL

Parameters::

    ** LPCWSTR lptstrFilename filepath
    *  DWORD dwHandle
    *  DWORD dwLen
    *  LPVOID lpData

Logging::

    b buffer dwLen, lpData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetForegroundWindow
===================

Signature::

    * Library: user32
    * Return value: HWND

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetInterfaceInfo
================

Signature::

    * Is success: ret == NO_ERROR
    * Library: iphlpapi
    * Return value: DWORD

Parameters::

    *  PIP_INTERFACE_INFO pIfTable
    *  PULONG dwOutBufLen

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetKeyState
===========

Signature::

    * Library: user32
    * Return value: SHORT

Parameters::

    ** int nVirtKey

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetKeyboardState
================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** PBYTE lpKeyState

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetSystemMetrics
================

Signature::

    * Library: user32
    * Return value: int

Parameters::

    ** int nIndex

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetVolumeNameForVolumeMountPointW
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszVolumeMountPoint
    ** LPWSTR lpszVolumeName
    ** DWORD cchBufferLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetVolumePathNameW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszFileName
    ** LPWSTR lpszVolumePathName
    ** DWORD cchBufferLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GlobalMemoryStatus
==================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPMEMORYSTATUS lpBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GlobalMemoryStatusEx
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPMEMORYSTATUSEX lpBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpOpenRequestA
================

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** HINTERNET hConnect connect_handle
    ** LPCTSTR lpszVerb http_method
    ** LPCTSTR lpszObjectName path
    ** LPCTSTR lpszVersion http_version
    ** LPCTSTR lpszReferer referer
    *  LPCTSTR *lplpszAcceptTypes
    ** DWORD dwFlags flags
    *  DWORD_PTR dwContext

Interesting::

    s http_method
    s path
    s http_version
    s referer
    i flags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpOpenRequestW
================

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** HINTERNET hConnect connect_handle
    ** LPWSTR lpszVerb http_method
    ** LPWSTR lpszObjectName path
    ** LPWSTR lpszVersion http_version
    ** LPWSTR lpszReferer referer
    *  LPWSTR *lplpszAcceptTypes
    ** DWORD dwFlags flags
    *  DWORD_PTR dwContext

Interesting::

    u http_method
    u path
    u http_version
    u referer
    i flags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpSendRequestA
================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hRequest request_handle
    *  LPCTSTR lpszHeaders
    *  DWORD dwHeadersLength
    *  LPVOID lpOptional
    *  DWORD dwOptionalLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    int headers_length = dwHeadersLength;
    if(lpszHeaders != NULL && headers_length == -1) {
        headers_length = copy_strlen(lpszHeaders);
    }

Interesting::

    S dwHeadersLength, lpszHeaders
    b dwOptionalLength, lpOptional

Logging::

    S headers headers_length, lpszHeaders
    b post_data (uintptr_t) dwOptionalLength, lpOptional


HttpSendRequestW
================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hRequest request_handle
    *  LPWSTR lpszHeaders
    *  DWORD dwHeadersLength
    *  LPVOID lpOptional
    *  DWORD dwOptionalLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    int headers_length = dwHeadersLength;
    if(lpszHeaders != NULL && headers_length == -1) {
        headers_length = copy_strlenW(lpszHeaders);
    }

Interesting::

    U dwHeadersLength, lpszHeaders
    b dwOptionalLength, lpOptional

Logging::

    U headers headers_length, lpszHeaders
    b post_data (uintptr_t) dwOptionalLength, lpOptional


IWbemServices_ExecMethod
========================

Signature::

    * Callback: addr
    * Library: __wmi__
    * Mode: exploit
    * Return value: HRESULT

Parameters::

    *  IWbemServices *This
    ** const wchar_t *strObjectPath class
    ** const wchar_t *strMethodName method
    ** long lFlags flags
    *  IWbemContext *pCtx
    *  IWbemClassObject *pInParams
    *  IWbemClassObject **ppOutParams
    *  IWbemCallResult **ppCallResult

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    int adjusted = -1; uint32_t creation_flags = 0;

    // We adjust some parameters for Win32_Process::Create so we can follow
    // the newly created process cleanly.
    if(wcscmp(strObjectPath, L"Win32_Process") == 0 &&
            wcscmp(strMethodName, L"Create") == 0) {
        adjusted = wmi_win32_process_create_pre(
            This, pInParams, &creation_flags
        );
    }

Post::

    HRESULT hr; VARIANT vt; uint32_t pid = 0, tid = 0;

    if(adjusted == 0 && SUCCEEDED(ret) != FALSE) {
        vt.vt = VT_EMPTY;
        hr = (*ppOutParams)->lpVtbl->Get(
            *ppOutParams, L"ProcessId", 0, &vt, NULL, NULL
        );
        if(SUCCEEDED(hr) != FALSE && vt.vt == VT_I4) {
            pid = vt.uintVal; tid = first_tid_from_pid(pid);
            pipe("PROCESS2:%d,%d,%d", pid, tid, HOOK_MODE_ALL);
        }

        if((creation_flags & CREATE_SUSPENDED) == 0 && tid != 0) {
            resume_thread_identifier(tid);
        }

        sleep_skip_disable();
    }


IWbemServices_ExecMethodAsync
=============================

Signature::

    * Callback: addr
    * Library: __wmi__
    * Mode: exploit
    * Return value: HRESULT

Parameters::

    *  IWbemServices *This
    ** const BSTR strObjectPath class
    ** const BSTR strMethodName method
    ** long lFlags flags
    *  IWbemContext *pCtx
    *  IWbemClassObject *pInParams
    *  IWbemObjectSink *pResponseHandler

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    // TODO Implement process following functionality.


IWbemServices_ExecQuery
=======================

Signature::

    * Callback: addr
    * Library: __wmi__
    * Mode: exploit
    * Return value: HRESULT

Parameters::

    *  IWbemServices *This
    ** const BSTR strQueryLanguage query_language
    ** const BSTR strQuery query
    ** ULONG lFlags flags
    *  IWbemContext *pCtx
    *  IEnumWbemClassObject **ppEnum

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


IWbemServices_ExecQueryAsync
============================

Signature::

    * Callback: addr
    * Library: __wmi__
    * Mode: exploit
    * Return value: HRESULT

Parameters::

    *  IWbemServices *This
    ** const BSTR strQueryLanguage query_language
    ** const BSTR strQuery query
    ** long lFlags flags
    *  IWbemContext *pCtx
    *  IWbemObjectSink *pResponseHandler

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetCloseHandle
===================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hInternet internet_handle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetConnectA
================

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** HINTERNET hInternet internet_handle
    ** LPCTSTR lpszServerName hostname
    ** INTERNET_PORT nServerPort port
    ** LPCTSTR lpszUsername username
    ** LPCTSTR lpszPassword password
    ** DWORD dwService service
    ** DWORD dwFlags flags
    *  DWORD_PTR dwContext

Interesting::

    s hostname
    i port
    s username
    s password
    i service
    i flags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetConnectW
================

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** HINTERNET hInternet internet_handle
    ** LPWSTR lpszServerName hostname
    ** INTERNET_PORT nServerPort port
    ** LPWSTR lpszUsername username
    ** LPWSTR lpszPassword password
    ** DWORD dwService service
    ** DWORD dwFlags flags
    *  DWORD_PTR dwContext

Interesting::

    u hostname
    i port
    u username
    u password
    i service
    i flags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetGetConnectedState
=========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPDWORD lpdwFlags flags
    *  DWORD dwReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetOpenA
=============

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** LPCTSTR lpszAgent user_agent
    ** DWORD dwAccessType access_type
    ** LPCTSTR lpszProxyName proxy_name
    ** LPCTSTR lpszProxyBypass proxy_bypass
    ** DWORD dwFlags flags

Interesting::

    s user_agent
    i access_type
    s proxy_name
    s proxy_bypass
    i flags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetOpenUrlA
================

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** HINTERNET hInternet internet_handle
    ** LPCTSTR lpszUrl url
    *  LPCTSTR lpszHeaders
    *  DWORD dwHeadersLength
    ** DWORD dwFlags flags
    *  DWORD_PTR dwContext

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    int headers_length = dwHeadersLength;
    if(lpszHeaders != NULL && headers_length == -1) {
        headers_length = copy_strlen(lpszHeaders);
    }

Interesting::

    s url
    S headers_length, lpszHeaders
    i flags

Logging::

    b headers (uintptr_t) headers_length, lpszHeaders


InternetOpenUrlW
================

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** HINTERNET hInternet
    ** LPWSTR lpszUrl url
    *  LPWSTR lpszHeaders
    *  DWORD dwHeadersLength
    ** DWORD dwFlags flags
    *  DWORD_PTR dwContext

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    int headers_length = dwHeadersLength;
    if(lpszHeaders != NULL && headers_length == -1) {
        headers_length = copy_strlenW(lpszHeaders);
    }

Interesting::

    u url
    U headers_length, lpszHeaders
    i flags

Logging::

    b headers (uintptr_t) headers_length, lpszHeaders


InternetOpenW
=============

Signature::

    * Library: wininet
    * Return value: HINTERNET

Parameters::

    ** LPWSTR lpszAgent user_agent
    ** DWORD dwAccessType access_type
    ** LPWSTR lpszProxyName proxy_name
    ** LPWSTR lpszProxyBypass proxy_bypass
    ** DWORD dwFlags flags

Interesting::

    u user_agent
    i access_type
    u proxy_name
    u proxy_bypass
    i flags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetQueryOptionA
====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hInternet internet_handle
    ** DWORD dwOption option
    *  LPVOID lpBuffer
    *  LPDWORD lpdwBufferLength

Flags::

    option

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetReadFile
================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hFile request_handle
    *  LPVOID lpBuffer
    *  DWORD dwNumberOfBytesToRead
    *  LPDWORD lpdwNumberOfBytesRead

Ensure::

    lpdwNumberOfBytesRead

Logging::

    b buffer (uintptr_t) copy_uint32(lpdwNumberOfBytesRead), lpBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetSetOptionA
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hInternet internet_handle
    ** DWORD dwOption option
    *  LPVOID lpBuffer
    *  DWORD dwBufferLength

Flags::

    option

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetSetStatusCallback
=========================

Signature::

    * Is success: 1
    * Library: wininet
    * Return value: INTERNET_STATUS_CALLBACK

Parameters::

    ** HINTERNET hInternet internet_handle
    ** INTERNET_STATUS_CALLBACK lpfnInternetCallback callback

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetWriteFile
=================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HINTERNET hFile request_handle
    *  LPCVOID lpBuffer
    *  DWORD dwNumberOfBytesToWrite
    *  LPDWORD lpdwNumberOfBytesWritten

Ensure::

    lpdwNumberOfBytesWritten

Logging::

    b buffer (uintptr_t) copy_uint32(lpdwNumberOfBytesWritten), lpBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


IsDebuggerPresent
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


LoadResource
============

Signature::

    * Library: kernel32
    * Return value: HGLOBAL

Parameters::

    ** HMODULE hModule
    ** HRSRC hResInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


LoadStringA
===========

Signature::

    * Library: user32
    * Return value: int

Parameters::

    ** HINSTANCE hInstance
    ** UINT uID
    ** LPSTR lpBuffer
    ** int cchBufferMax

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


LoadStringW
===========

Signature::

    * Library: user32
    * Return value: int

Parameters::

    ** HINSTANCE hInstance
    ** UINT uID
    ** LPWSTR lpBuffer
    ** int cchBufferMax

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


LookupAccountSidW
=================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpSystemName
    ** PSID Sid
    ** LPWSTR Name
    ** LPDWORD cchName
    ** LPWSTR ReferencedDomainName
    ** LPDWORD cchReferencedDomainName
    ** PSID_NAME_USE peUse

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


LookupPrivilegeValueW
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpSystemName
    ** LPCWSTR lpName
    ** PLUID lpLuid

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


MessageBoxTimeoutA
==================

Signature::

    * Library: user32
    * Is success: ret != 0
    * Return value: int

Parameters::

    ** HWND hWnd window_handle
    ** LPCTSTR lpText text
    ** LPCTSTR lpCaption caption
    ** UINT uType flags
    ** WORD wLanguageId language_identifier
    *  INT Unknown

Interesting::

    s text
    s caption
    i flags
    i language_identifier

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


MessageBoxTimeoutW
==================

Signature::

    * Library: user32
    * Is success: ret != 0
    * Return value: int

Parameters::

    ** HWND hWnd window_handle
    ** LPWSTR lpText text
    ** LPWSTR lpCaption caption
    ** UINT uType flags
    ** WORD wLanguageId language_identifier
    *  INT Unknown

Interesting::

    u text
    u caption
    i flags
    i language_identifier

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


Module32FirstW
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot
    ** LPMODULEENTRY32W lpme

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


Module32NextW
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot
    ** LPMODULEENTRY32W lpme

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


NetGetJoinInformation
=====================

Signature::

    * Library: netapi32
    * Return value: NET_API_STATUS

Parameters::

    ** LPCWSTR lpServer server
    *  LPWSTR *lpNameBuffer
    *  PNETSETUP_JOIN_STATUS BufferType

Ensure::

    lpNameBuffer

Logging::

    u name *lpNameBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


NetShareEnum
============

Signature::

    * Library: netapi32
    * Return value: NET_API_STATUS

Parameters::

    ** LPWSTR servername servername
    ** DWORD level level
    *  LPBYTE *bufptr
    *  DWORD prefmaxlen
    *  LPDWORD entriesread
    *  LPDWORD totalentries
    *  LPDWORD resume_handle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


NetUserGetInfo
==============

Signature::

    * Library: netapi32
    * Is success: ret == 0
    * Return value: int

Parameters::

    ** LPCWSTR servername server_name
    ** LPCWSTR username username
    ** DWORD level level
    *  LPBYTE *bufptr

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


NetUserGetLocalGroups
=====================

Signature::

    * Library: netapi32
    * Return value: NET_API_STATUS

Parameters::

    ** LPCWSTR servername servername
    ** LPCWSTR username username
    ** DWORD level level
    ** DWORD flags flags
    *  LPBYTE *bufptr
    *  DWORD prefmaxlen
    *  LPDWORD entriesread
    *  LPDWORD totalentries

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ObtainUserAgentString
=====================

Signature::

    * Library: urlmon
    * Return value: HRESULT

Parameters::

    ** DWORD dwOption option
    *  LPSTR pcszUAOut
    *  DWORD *cbSize

Ensure::

    cbSize

Middle::

    uint32_t length = ret == S_OK ? copy_uint32(cbSize) : 0;

Logging::

    S user_agent length, pcszUAOut

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OleConvertOLESTREAMToIStorage
=============================

Signature::

    * Library: ole32
    * Mode: exploit
    * Return value: HRESULT

Parameters::

    *  LPOLESTREAM lpolestream
    *  IStorage *pstg
    *  const DVTARGETDEVICE *ptd

Middle::

    void *buf = NULL; uintptr_t len = 0;

    #if !__x86_64__
    if(lpolestream != NULL) {
        buf = copy_ptr(copy_ptr((uint8_t *) lpolestream + 8));
        len = copy_uint32((uint8_t *) lpolestream + 12);
    }
    #endif

Logging::

    !b ole2 len, buf

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OleInitialize
=============

Signature::

    * Library: ole32
    * Mode: exploit
    * Return value: HRESULT

Parameters::

    *  LPVOID pvReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OutputDebugStringA
==================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPCSTR lpOutputString

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


PRF
===

Signature::

    * Callback: module
    * Library: ncrypt
    * Mode: dumptls
    * Prune: resolve
    * Return value: NTSTATUS

Parameters::

    *  void *unk1
    *  uintptr_t unk2
    *  uint8_t *buf1
    *  uintptr_t buf1_length
    ** const char *type
    *  uint32_t type_length
    *  uint8_t *buf2
    *  uint32_t buf2_length
    *  uint8_t *buf3
    *  uint32_t buf3_length

Middle::

    uintptr_t master_secret_length = 0, random_length = 0;
    uint8_t *master_secret = NULL, *client_random = NULL;
    uint8_t *server_random = NULL;

    char client_random_repr[32*2+1] = {};
    char server_random_repr[32*2+1] = {};
    char master_secret_repr[48*2+1] = {};

    if(type_length == 13 && strcmp(type, "key expansion") == 0 &&
            buf2_length == 64) {
        master_secret_length = buf1_length;
        master_secret = buf1;

        random_length = 32;
        server_random = buf2;
        client_random = buf2 + random_length;

        hexencode(client_random_repr, client_random, random_length);
        hexencode(server_random_repr, server_random, random_length);
        hexencode(master_secret_repr, master_secret, master_secret_length);
    }

Logging::

    s client_random client_random_repr
    s server_random server_random_repr
    s master_secret master_secret_repr

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ReadCabinetState
================

Signature::

    * Library: shell32
    * Return value: BOOL

Parameters::

    *  CABINETSTATE *pcs
    *  int cLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegEnumKeyW
===========

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    ** HKEY hKey
    ** DWORD dwIndex
    ** LPWSTR lpName
    ** DWORD cchName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RegisterHotKey
==============

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** HWND hWnd
    ** int id
    ** UINT fsModifiers
    ** UINT vk

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SHGetFolderPathW
================

Signature::

    * Library: shell32
    * Return value: HRESULT

Parameters::

    ** HWND hwndOwner owner_handle
    ** int nFolder folder
    ** HANDLE hToken token_handle
    ** DWORD dwFlags flags
    *  LPWSTR pszPath

Flags::

    folder

Middle::

    wchar_t *dirpath = get_unicode_buffer();
    path_get_full_pathW(pszPath, dirpath);

Logging::

    u dirpath dirpath
    u dirpath_r pszPath

Post::

    free_unicode_buffer(dirpath);

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SHGetSpecialFolderLocation
==========================

Signature::

    * Library: shell32
    * Return value: HRESULT

Parameters::

    ** HWND hwndOwner window_handle
    ** int nFolder folder_index
    *  void *ppidl

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SendNotifyMessageA
==================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** HWND hWnd
    ** UINT Msg
    ** WPARAM wParam
    ** LPARAM lParam

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    uint32_t pid = 0, tid;

    // TODO Will this still happen before the notify message is executed?
    tid = get_window_thread_process_id(hWnd, &pid);
    pipe("PROCESS2:%d,%d,%d", pid, tid, HOOK_MODE_ALL);


SendNotifyMessageW
==================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** HWND hWnd
    ** UINT Msg
    ** WPARAM wParam
    ** LPARAM lParam

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    uint32_t pid = 0, tid;

    // TODO Will this still happen before the notify message is executed?
    tid = get_window_thread_process_id(hWnd, &pid);
    pipe("PROCESS2:%d,%d,%d", pid, tid, HOOK_MODE_ALL);


SetErrorMode
============

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    ** UINT uMode

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetUnhandledExceptionFilter
===========================

Signature::

    * Library: kernel32
    * Return value: LPTOP_LEVEL_EXCEPTION_FILTER

Parameters::

    ** LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ShellExecuteExW
===============

Signature::

    * Library: shell32
    * Mode: exploit
    * Return value: BOOL

Parameters::

    *  SHELLEXECUTEINFOW *pExecInfo

Ensure::

    pExecInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    SHELLEXECUTEINFOW sei;
    memset(&sei, 0, sizeof(SHELLEXECUTEINFOW));

    wchar_t *filepath = get_unicode_buffer();
    if(pExecInfo != NULL &&
            copy_bytes(&sei, pExecInfo, sizeof(SHELLEXECUTEINFOW)) == 0 &&
            sei.lpFile != NULL) {
        // In case it's a relative path we'll just stick to it.
        copy_unicodez(filepath, sei.lpFile);

        // If this is not a relative path then we resolve the full path.
        if(lstrlenW(filepath) > 2 && filepath[1] == ':' &&
                filepath[2] == '\\') {
            path_get_full_pathW(sei.lpFile, filepath);
        }
    }

Interesting::

    u filepath
    i sei.fMask
    u sei.lpVerb
    u sei.lpFile
    u sei.lpParameters
    u sei.lpDirectory
    i sei.nShow
    u sei.lpClass
    i sei.dwHotKey

Logging::

    u filepath filepath
    u filepath_r sei.lpFile
    u parameters sei.lpParameters
    i show_type sei.nShow

Post::

    free_unicode_buffer(filepath);


SizeofResource
==============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HMODULE hModule
    ** HRSRC hResInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


Ssl3GenerateKeyMaterial
=======================

Signature::

    * Callback: module
    * Library: ncrypt
    * Mode: dumptls
    * Prune: resolve
    * Return value: NTSTATUS

Parameters::

    *  uintptr_t unk1
    *  uint8_t *secret
    *  uintptr_t secret_length
    *  uint8_t *seed
    *  uintptr_t seed_length
    *  void *unk2
    *  uintptr_t unk3

Middle::

    uintptr_t random_length = 32;
    uint8_t *client_random = seed;
    uint8_t *server_random = seed + random_length;

    char client_random_repr[32*2+1] = {};
    char server_random_repr[32*2+1] = {};
    char master_secret_repr[48*2+1] = {};

    if(seed_length == 64 && secret_length == 48) {
        hexencode(client_random_repr, client_random, random_length);
        hexencode(server_random_repr, server_random, random_length);
        hexencode(master_secret_repr, secret, secret_length);
    }

Logging::

    s client_random client_random_repr
    s server_random server_random_repr
    s master_secret master_secret_repr

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


TaskDialog
==========

Signature::

    * Library: comctl32
    * Prune: resolve
    * Return value: HRESULT

Parameters::

    ** HWND hWndParent parent_window_handle
    ** HINSTANCE hInstance instance_handle
    *  PCWSTR pszWindowTitle
    *  PCWSTR pszMainInstruction
    *  PCWSTR pszContent
    ** TASKDIALOG_COMMON_BUTTON_FLAGS dwCommonButtons buttons
    *  PCWSTR pszIcon
    ** int *pnButton button

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

    wchar_t title_buf[10], description_buf[10], content_buf[10], icon_buf[10];
    wchar_t *title, *description, *content, *icon;

    int_or_strW(&title, pszWindowTitle, title_buf);
    int_or_strW(&description, pszMainInstruction, description_buf);
    int_or_strW(&content, pszContent, content_buf);
    int_or_strW(&icon, pszIcon, icon_buf);

Logging::

    u title title
    u description description
    u content content
    u icon icon


Thread32First
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot
    ** LPTHREADENTRY32 lpte

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


Thread32Next
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot
    ** LPTHREADENTRY32 lpte

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


TransmitFile
============

Signature::

    * Library: ws2_32
    * Prune: resolve
    * Return value: BOOL

Parameters::

    ** SOCKET hSocket socket
    ** HANDLE hFile file_handle
    ** DWORD nNumberOfBytesToWrite
    ** DWORD nNumberOfBytesPerSend
    *  LPOVERLAPPED lpOverlapped
    *  LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers
    *  DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


UuidCreate
==========

Signature::

    * Is success: 1
    * Library: rpcrt4
    * Return value: RPC_STATUS

Parameters::

    *  UUID *Uuid

Middle::

    char uuid[128];
    clsid_to_string(Uuid, uuid);

Logging::

    s uuid uuid

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WNetGetProviderNameW
====================

Signature::

    * Is success: ret == NO_ERROR
    * Library: mpr
    * Return value: DWORD

Parameters::

    *  DWORD dwNetType
    *  LPTSTR lpProviderName
    *  LPDWORD lpBufferSize

Ensure::

    lpBufferSize

Logging::

    x net_type dwNetType

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WriteConsoleA
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** const VOID *lpBuffer
    ** DWORD nNumberOfCharsToWrite
    ** LPDWORD lpNumberOfCharsWritten
    ** LPVOID lpReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WriteConsoleW
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hConsoleOutput
    ** const VOID *lpBuffer
    ** DWORD nNumberOfCharsToWrite
    ** LPDWORD lpNumberOfCharsWritten
    ** LPVOID lpReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


system
======

Signature::

    * Is success: ret == 0
    * Library: msvcrt
    * Return value: int

Parameters::

    ** const char *command

Interesting::

    s command

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


timeGetTime
===========

Signature::

    * Is success: 1
    * Library: winmm
    * Return value: DWORD

Post::

    ret += sleep_skipped() / 10000;

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CompareFileTime
===============

Signature::

    * Library: kernel32
    * Return value: LONG

Parameters::

    ** const FILETIME *lpFileTime1
    ** const FILETIME *lpFileTime2

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DosDateTimeToFileTime
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** WORD wFatDate
    ** WORD wFatTime
    ** LPFILETIME lpFileTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


EnumDynamicTimeZoneInformation
==============================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** const DWORD dwIndex
    ** PDYNAMIC_TIME_ZONE_INFORMATION lpTimeZoneInformation

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FileTimeToDosDateTime
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const FILETIME *lpFileTime
    ** LPWORD lpFatDate
    ** LPWORD lpFatTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FileTimeToLocalFileTime
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const FILETIME *lpFileTime
    ** LPFILETIME lpLocalFileTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FileTimeToSystemTime
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const FILETIME *lpFileTime
    ** LPSYSTEMTIME lpSystemTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetDynamicTimeZoneInformation
=============================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** PDYNAMIC_TIME_ZONE_INFORMATION pTimeZoneInformation

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetDynamicTimeZoneInformationEffectiveYears
===========================================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    ** const PDYNAMIC_TIME_ZONE_INFORMATION lpTimeZoneInformation
    ** LPDWORD FirstYear
    ** LPDWORD LastYear

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetLocalTime
============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSYSTEMTIME lpSystemTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetSystemTime
=============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSYSTEMTIME lpSystemTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetSystemTimeAdjustment
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PDWORD lpTimeAdjustment
    ** PDWORD lpTimeIncrement
    ** PBOOL lpTimeAdjustmentDisabled

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetSystemTimeAsFileTime
=======================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPFILETIME lpSystemTimeAsFileTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetSystemTimes
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PFILETIME lpIdleTime
    ** PFILETIME lpKernelTime
    ** PFILETIME lpUserTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetTickCount
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetTickCount64
==============

Signature::

    * Library: kernel32
    * Return value: ULONGLONG

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetTimeFormatA
==============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwFlags
    ** const SYSTEMTIME *lpTime
    ** LPCSTR lpFormat
    ** LPSTR lpTimeStr
    ** int cchTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetTimeFormatW
==============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** LCID Locale
    ** DWORD dwFlags
    ** const SYSTEMTIME *lpTime
    ** LPCWSTR lpFormat
    ** LPWSTR lpTimeStr
    ** int cchTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetTimeZoneInformation
======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPTIME_ZONE_INFORMATION lpTimeZoneInformation

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetTimeZoneInformationForYear
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** USHORT wYear
    ** PDYNAMIC_TIME_ZONE_INFORMATION pdtzi
    ** LPTIME_ZONE_INFORMATION ptzi

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


LocalFileTimeToFileTime
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const FILETIME *lpLocalFileTime
    ** LPFILETIME lpFileTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueryUnbiasedInterruptTime
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PULONGLONG UnbiasedTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetDynamicTimeZoneInformation
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const DYNAMIC_TIME_ZONE_INFORMATION *lpTimeZoneInformation

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetFileTime
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** const FILETIME *lpCreationTime
    ** const FILETIME *lpLastAccessTime
    ** const FILETIME *lpLastWriteTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetLocalTime
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const SYSTEMTIME *lpSystemTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetSystemTime
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const SYSTEMTIME *lpSystemTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetSystemTimeAdjustment
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwTimeAdjustment
    ** BOOL bTimeAdjustmentDisabled

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetTimeZoneInformation
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const TIME_ZONE_INFORMATION *lpTimeZoneInformation

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SystemTimeToFileTime
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const SYSTEMTIME *lpSystemTime
    ** LPFILETIME lpFileTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SystemTimeToTzSpecificLocalTime
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const TIME_ZONE_INFORMATION *lpTimeZoneInformation
    ** const SYSTEMTIME *lpUniversalTime
    ** LPSYSTEMTIME lpLocalTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SystemTimeToTzSpecificLocalTimeEx
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const DYNAMIC_TIME_ZONE_INFORMATION *lpTimeZoneInformation
    ** const SYSTEMTIME *lpUniversalTime
    ** LPSYSTEMTIME lpLocalTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


TzSpecificLocalTimeToSystemTime
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const TIME_ZONE_INFORMATION *lpTimeZoneInformation
    ** const SYSTEMTIME *lpLocalTime
    ** LPSYSTEMTIME lpUniversalTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


TzSpecificLocalTimeToSystemTimeEx
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** const DYNAMIC_TIME_ZONE_INFORMATION *lpTimeZoneInformation
    ** const SYSTEMTIME *lpLocalTime
    ** LPSYSTEMTIME lpUniversalTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CallMsgFilterA
==============

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** LPMSG lpMsg
    ** int nCode

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CallMsgFilterW
==============

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** LPMSG lpMsg
    ** int nCode

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


UnhookWindowsHookEx
===================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** HHOOK hhk

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CancelWaitableTimer
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hTimer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ClosePrivateNamespace
=====================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    ** HANDLE Handle
    ** ULONG Flags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateMutexA
============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpMutexAttributes
    ** BOOL bInitialOwner
    ** LPCSTR lpName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateMutexW
============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpMutexAttributes
    ** BOOL bInitialOwner
    ** LPCWSTR lpName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreatePrivateNamespaceA
=======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpPrivateNamespaceAttributes
    ** LPVOID lpBoundaryDescriptor
    ** LPCSTR lpAliasPrefix

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreatePrivateNamespaceW
=======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpPrivateNamespaceAttributes
    ** LPVOID lpBoundaryDescriptor
    ** LPCWSTR lpAliasPrefix

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateTimerQueue
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateWaitableTimerA
====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpTimerAttributes
    ** BOOL bManualReset
    ** LPCSTR lpTimerName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateWaitableTimerW
====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpTimerAttributes
    ** BOOL bManualReset
    ** LPCWSTR lpTimerName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DeleteSynchronizationBarrier
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPSYNCHRONIZATION_BARRIER lpBarrier

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DeleteTimerQueue
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE TimerQueue

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DeleteTimerQueueEx
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE TimerQueue
    ** HANDLE CompletionEvent

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DeleteTimerQueueTimer
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE TimerQueue
    ** HANDLE Timer
    ** HANDLE CompletionEvent

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


EnterSynchronizationBarrier
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPSYNCHRONIZATION_BARRIER lpBarrier
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InitializeSynchronizationBarrier
================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPSYNCHRONIZATION_BARRIER lpBarrier
    ** LONG lTotalThreads
    ** LONG lSpinCount

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenEventA
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCSTR lpName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenEventW
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCWSTR lpName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenMutexA
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCSTR lpName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenMutexW
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCWSTR lpName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenPrivateNamespaceA
=====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPVOID lpBoundaryDescriptor
    ** LPCSTR lpAliasPrefix

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenPrivateNamespaceW
=====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPVOID lpBoundaryDescriptor
    ** LPCWSTR lpAliasPrefix

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenSemaphoreA
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCSTR lpName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenSemaphoreW
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCWSTR lpName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenWaitableTimerA
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCSTR lpTimerName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenWaitableTimerW
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCWSTR lpTimerName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


PulseEvent
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hEvent

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ReleaseMutex
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hMutex

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ReleaseSemaphore
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSemaphore
    ** LONG lReleaseCount
    ** LPLONG lpPreviousCount

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ResetEvent
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hEvent

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetEvent
========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hEvent

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SleepConditionVariableCS
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PCONDITION_VARIABLE ConditionVariable
    ** PCRITICAL_SECTION CriticalSection
    ** DWORD dwMilliseconds

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


UnregisterWait
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE WaitHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


UnregisterWaitEx
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE WaitHandle
    ** HANDLE CompletionEvent

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WaitForMultipleObjects
======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nCount
    ** const HANDLE *lpHandles
    ** BOOL bWaitAll
    ** DWORD dwMilliseconds

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WaitForMultipleObjectsEx
========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD nCount
    ** const HANDLE *lpHandles
    ** BOOL bWaitAll
    ** DWORD dwMilliseconds
    ** BOOL bAlertable

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WaitForSingleObject
===================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hHandle
    ** DWORD dwMilliseconds

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WaitForSingleObjectEx
=====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hHandle
    ** DWORD dwMilliseconds
    ** BOOL bAlertable

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WakeAllConditionVariable
========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PCONDITION_VARIABLE ConditionVariable

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WakeConditionVariable
=====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PCONDITION_VARIABLE ConditionVariable

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CommitUrlCacheEntryA
====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrlName
    ** LPCSTR lpszLocalFileName
    ** FILETIME ExpireTime
    ** FILETIME LastModifiedTime
    ** DWORD CacheEntryType
    ** LPBYTE lpHeaderInfo
    ** DWORD cchHeaderInfo
    ** LPCSTR lpszFileExtension
    ** LPCSTR lpszOriginalUrl

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CommitUrlCacheEntryW
====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszUrlName
    ** LPCWSTR lpszLocalFileName
    ** FILETIME ExpireTime
    ** FILETIME LastModifiedTime
    ** DWORD CacheEntryType
    ** LPWSTR lpszHeaderInfo
    ** DWORD cchHeaderInfo
    ** LPCWSTR lpszFileExtension
    ** LPCWSTR lpszOriginalUrl

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DnsCancelQuery
==============

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    ** PDNS_QUERY_CANCEL pCancelHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DnsFree
=======

Signature::

    * Library: dnsapi
    * Return value: void

Parameters::

    ** PVOID pData
    ** DNS_FREE_TYPE FreeType

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DnsFreeProxyName
================

Signature::

    * Library: dnsapi
    * Return value: void

Parameters::

    ** PWSTR proxyName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DnsQueryEx
==========

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    ** PDNS_QUERY_REQUEST pQueryRequest
    ** PDNS_QUERY_RESULT pQueryResults
    ** PDNS_QUERY_CANCEL pCancelHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DnsRecordCompare
================

Signature::

    * Library: dnsapi
    * Return value: BOOL

Parameters::

    ** PDNS_RECORD pRecord1
    ** PDNS_RECORD pRecord2

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DnsRecordCopyEx
===============

Signature::

    * Library: dnsapi
    * Return value: PDNS_RECORD

Parameters::

    ** PDNS_RECORD pRecord
    ** DNS_CHARSET CharSetIn
    ** DNS_CHARSET CharSetOut

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DnsRecordListFree
=================

Signature::

    * Library: dnsapi
    * Return value: void

Parameters::

    ** PDNS_RECORD pRecordList
    ** DNS_FREE_TYPE FreeType

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DnsRecordSetCopyEx
==================

Signature::

    * Library: dnsapi
    * Return value: PDNS_RECORD

Parameters::

    ** PDNS_RECORD pRecordSet
    ** DNS_CHARSET CharSetIn
    ** DNS_CHARSET CharSetOut

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DnsReleaseContextHandle
=======================

Signature::

    * Library: dnsapi
    * Return value: void

Parameters::

    ** HANDLE hContext

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindNextUrlCacheEntryA
======================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HANDLE hEnumHandle
    ** LPINTERNET_CACHE_ENTRY_INFOA lpNextCacheEntryInfo
    ** LPDWORD lpcbCacheEntryInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FindNextUrlCacheEntryW
======================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HANDLE hEnumHandle
    ** LPINTERNET_CACHE_ENTRY_INFOW lpNextCacheEntryInfo
    ** LPDWORD lpcbCacheEntryInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FreeAddrInfoEx
==============

Signature::

    * Library: ws2_32
    * Return value: void

Parameters::

    ** PADDRINFOEXA pAddrInfoEx

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FreeAddrInfoExW
===============

Signature::

    * Library: ws2_32
    * Return value: void

Parameters::

    ** PADDRINFOEXW pAddrInfoEx

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FreeAddrInfoW
=============

Signature::

    * Library: ws2_32
    * Return value: void

Parameters::

    ** PADDRINFOW pAddrInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetAddrInfoExA
==============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** PCSTR pName
    ** PCSTR pServiceName
    ** DWORD dwNameSpace
    ** LPGUID lpNspId
    ** const ADDRINFOEXA *hints
    ** PADDRINFOEXA *ppResult
    ** struct timeval *timeout
    ** LPOVERLAPPED lpOverlapped
    ** LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine
    ** LPHANDLE lpNameHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetAddrInfoExW
==============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** PCWSTR pName
    ** PCWSTR pServiceName
    ** DWORD dwNameSpace
    ** LPGUID lpNspId
    ** const ADDRINFOEXW *hints
    ** PADDRINFOEXW *ppResult
    ** struct timeval *timeout
    ** LPOVERLAPPED lpOverlapped
    ** LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine
    ** LPHANDLE lpHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetAddrInfoExCancel
===================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPHANDLE lpHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetAddrInfoExOverlappedResult
=============================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPOVERLAPPED lpOverlapped

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetAddrInfoW
============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** PCWSTR pNodeName
    ** PCWSTR pServiceName
    ** const ADDRINFOW *pHints
    ** PADDRINFOW *ppResult

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetHostNameW
============

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** PWSTR name
    ** int namelen

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetUrlCacheEntryInfoA
=====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrlName
    ** LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo
    ** LPDWORD lpcbCacheEntryInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetUrlCacheEntryInfoW
=====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszUrlName
    ** LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo
    ** LPDWORD lpcbCacheEntryInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetUrlCacheEntryInfoExA
=======================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrl
    ** LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo
    ** LPDWORD lpcbCacheEntryInfo
    ** LPSTR lpszRedirectUrl
    ** LPDWORD lpcbRedirectUrl
    ** LPVOID lpReserved
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetUrlCacheEntryInfoExW
=======================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszUrl
    ** LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo
    ** LPDWORD lpcbCacheEntryInfo
    ** LPWSTR lpszRedirectUrl
    ** LPDWORD lpcbRedirectUrl
    ** LPVOID lpReserved
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpAddUrl
==========

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** PCWSTR pFullyQualifiedUrl
    ** PVOID pReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpCloseRequestQueue
=====================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpCloseServerSession
======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTP_SERVER_SESSION_ID ServerSessionId

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpCloseUrlGroup
=================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTP_URL_GROUP_ID UrlGroupId

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpCreateHttpHandle
====================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** PHANDLE pReqQueueHandle
    ** ULONG Reserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpCreateServerSession
=======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTPAPI_VERSION Version
    ** PHTTP_SERVER_SESSION_ID pServerSessionId
    ** ULONG Reserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpCreateUrlGroup
==================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTP_SERVER_SESSION_ID ServerSessionId
    ** PHTTP_URL_GROUP_ID pUrlGroupId
    ** ULONG Reserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpInitialize
==============

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTPAPI_VERSION Version
    ** ULONG Flags
    ** PVOID pReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpRemoveUrl
=============

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** PCWSTR pFullyQualifiedUrl

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpRemoveUrlFromUrlGroup
=========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HTTP_URL_GROUP_ID UrlGroupId
    ** PCWSTR pFullyQualifiedUrl
    ** ULONG Flags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpShutdownRequestQueue
========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpTerminate
=============

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** ULONG Flags
    ** PVOID pReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpWaitForDemandStart
======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** LPOVERLAPPED pOverlapped

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


HttpWaitForDisconnect
=====================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    ** HANDLE ReqQueueHandle
    ** HTTP_CONNECTION_ID ConnectionId
    ** LPOVERLAPPED pOverlapped

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


IcmpCloseHandle
===============

Signature::

    * Library: icmp
    * Return value: BOOL

Parameters::

    ** HANDLE IcmpHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


IcmpCreateFile
==============

Signature::

    * Library: icmp
    * Return value: HANDLE

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


IcmpParseReplies
================

Signature::

    * Library: icmp
    * Return value: DWORD

Parameters::

    ** LPVOID ReplyBuffer
    ** DWORD ReplySize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InetPtonW
=========

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** INT Family
    ** PCWSTR pszAddrString
    ** PVOID pAddrBuf

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetCheckConnectionA
========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrl
    ** DWORD dwFlags
    ** DWORD dwReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetCheckConnectionW
========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszUrl
    ** DWORD dwFlags
    ** DWORD dwReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetCreateUrlA
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPURL_COMPONENTSA lpUrlComponents
    ** DWORD dwFlags
    ** LPSTR lpszUrl
    ** LPDWORD lpdwUrlLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetCreateUrlW
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPURL_COMPONENTSW lpUrlComponents
    ** DWORD dwFlags
    ** LPWSTR lpszUrl
    ** LPDWORD lpdwUrlLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetGetConnectedStateExA
============================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPDWORD lpdwFlags
    ** LPSTR lpszConnectionName
    ** DWORD cchNameLen
    ** DWORD dwReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetGetConnectedStateExW
============================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPDWORD lpdwFlags
    ** LPWSTR lpszConnectionName
    ** DWORD cchNameLen
    ** DWORD dwReserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetGetLastResponseInfoA
============================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPDWORD lpdwError
    ** LPSTR lpszBuffer
    ** LPDWORD lpdwBufferLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetGetLastResponseInfoW
============================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPDWORD lpdwError
    ** LPWSTR lpszBuffer
    ** LPDWORD lpdwBufferLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetSetCookieA
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCSTR lpszUrl
    ** LPCSTR lpszCookieName
    ** LPCSTR lpszCookieData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InternetSetCookieW
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpszUrl
    ** LPCWSTR lpszCookieName
    ** LPCWSTR lpszCookieData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RpcCertGeneratePrincipalNameA
=============================

Signature::

    * Library: rpcrt4
    * Return value: RPC_STATUS

Parameters::

    ** PCCERT_CONTEXT Context
    ** DWORD Flags
    ** RPC_CSTR *pBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


RpcCertGeneratePrincipalNameW
=============================

Signature::

    * Library: rpcrt4
    * Return value: RPC_STATUS

Parameters::

    ** PCCERT_CONTEXT Context
    ** DWORD Flags
    ** RPC_WSTR *pBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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


UnlockUrlCacheEntryStream
=========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    ** HANDLE hUrlCacheStream
    ** DWORD Reserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSACancelAsyncRequest
=====================

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** HANDLE hAsyncTaskHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSACloseEvent
=============

Signature::

    * Library: ws2_32
    * Return value: BOOL

Parameters::

    ** WSAEVENT hEvent

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSADuplicateSocketA
===================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** DWORD dwProcessId
    ** LPWSAPROTOCOL_INFOA lpProtocolInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSADuplicateSocketW
===================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** DWORD dwProcessId
    ** LPWSAPROTOCOL_INFOW lpProtocolInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAEnumNameSpaceProvidersA
==========================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPDWORD lpdwBufferLength
    ** LPWSANAMESPACE_INFOA lpnspBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAEnumNameSpaceProvidersW
==========================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPDWORD lpdwBufferLength
    ** LPWSANAMESPACE_INFOW lpnspBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAEnumNameSpaceProvidersExA
============================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPDWORD lpdwBufferLength
    ** LPWSANAMESPACE_INFOEXA lpnspBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAEnumNameSpaceProvidersExW
============================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPDWORD lpdwBufferLength
    ** LPWSANAMESPACE_INFOEXW lpnspBuffer

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAEnumNetworkEvents
====================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** WSAEVENT hEventObject
    ** LPWSANETWORKEVENTS lpNetworkEvents

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAEnumProtocolsA
=================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** LPINT lpiProtocols
    ** LPWSAPROTOCOL_INFOA lpProtocolBuffer
    ** LPDWORD lpdwBufferLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAEnumProtocolsW
=================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** LPINT lpiProtocols
    ** LPWSAPROTOCOL_INFOW lpProtocolBuffer
    ** LPDWORD lpdwBufferLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAEventSelect
==============

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** WSAEVENT hEventObject
    ** long lNetworkEvents

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAGetQOSByName
===============

Signature::

    * Library: ws2_32
    * Return value: BOOL

Parameters::

    ** SOCKET s
    ** LPWSABUF lpQOSName
    ** LPQOS lpQOS

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAGetServiceClassNameByClassIdA
================================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPGUID lpServiceClassId
    ** LPSTR lpszServiceClassName
    ** LPDWORD lpdwBufferLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAGetServiceClassNameByClassIdW
================================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPGUID lpServiceClassId
    ** LPWSTR lpszServiceClassName
    ** LPDWORD lpdwBufferLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAHtonl
========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** u_long hostlong
    ** u_long *lpnetlong

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAHtons
========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** u_short hostshort
    ** u_short *lpnetshort

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAInstallServiceClassA
=======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPWSASERVICECLASSINFOA lpServiceClassInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAInstallServiceClassW
=======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPWSASERVICECLASSINFOW lpServiceClassInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSALookupServiceBeginA
======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPWSAQUERYSETA lpqsRestrictions
    ** DWORD dwControlFlags
    ** LPHANDLE lphLookup

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSALookupServiceBeginW
======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPWSAQUERYSETW lpqsRestrictions
    ** DWORD dwControlFlags
    ** LPHANDLE lphLookup

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSALookupServiceEnd
===================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** HANDLE hLookup

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSANtohl
========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** u_long netlong
    ** u_long *lphostlong

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSANtohs
========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** u_short netshort
    ** u_short *lphostshort

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAPoll
=======

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** LPWSAPOLLFD fdArray
    ** ULONG fds
    ** INT timeout

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAProviderConfigChange
=======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPHANDLE lpNotificationHandle
    ** LPWSAOVERLAPPED lpOverlapped
    ** LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSARecvDisconnect
=================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** LPWSABUF lpInboundDisconnectData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSARemoveServiceClass
=====================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPGUID lpServiceClassId

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAResetEvent
=============

Signature::

    * Library: ws2_32
    * Return value: BOOL

Parameters::

    ** WSAEVENT hEvent

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSASendDisconnect
=================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    ** SOCKET s
    ** LPWSABUF lpOutboundDisconnectData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSASetEvent
===========

Signature::

    * Library: ws2_32
    * Return value: BOOL

Parameters::

    ** WSAEVENT hEvent

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSASetLastError
===============

Signature::

    * Library: wsock32
    * Return value: void

Parameters::

    ** int iError

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSASetServiceA
==============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPWSAQUERYSETA lpqsRegInfo
    ** WSAESETSERVICEOP essoperation
    ** DWORD dwControlFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSASetServiceW
==============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** LPWSAQUERYSETW lpqsRegInfo
    ** WSAESETSERVICEOP essoperation
    ** DWORD dwControlFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WSAStartup
==========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** WORD wVersionRequested
    ** LPWSADATA lpWSAData

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


accept
======

Signature::

    * Library: wsock32
    * Return value: SOCKET

Parameters::

    ** SOCKET s
    ** struct sockaddr *addr
    ** int *addrlen

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


bind
====

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** const struct sockaddr *name
    ** int namelen

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


closesocket
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


connect
=======

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** const struct sockaddr *name
    ** int namelen

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


freeaddrinfo
============

Signature::

    * Library: ws2_32
    * Return value: void

Parameters::

    ** PADDRINFOA pAddrInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


getaddrinfo
===========

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    ** PCSTR pNodeName
    ** PCSTR pServiceName
    ** const ADDRINFOA *pHints
    ** PADDRINFOA *ppResult

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


gethostbyaddr
=============

Signature::

    * Library: wsock32
    * Return value: struct hostent FAR *

Parameters::

    ** const char *addr
    ** int len
    ** int type

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


gethostbyname
=============

Signature::

    * Library: wsock32
    * Return value: struct hostent FAR *

Parameters::

    ** const char *name

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


gethostname
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** char *name
    ** int namelen

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


getpeername
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** struct sockaddr *name
    ** int *namelen

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


getprotobyname
==============

Signature::

    * Library: wsock32
    * Return value: struct protoent FAR *

Parameters::

    ** const char *name

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


getprotobynumber
================

Signature::

    * Library: wsock32
    * Return value: struct protoent FAR *

Parameters::

    ** int number

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


getservbyname
=============

Signature::

    * Library: wsock32
    * Return value: struct servent FAR *

Parameters::

    ** const char *name
    ** const char *proto

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


getservbyport
=============

Signature::

    * Library: wsock32
    * Return value: struct servent FAR *

Parameters::

    ** int port
    ** const char *proto

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


getsockname
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** struct sockaddr *name
    ** int *namelen

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


htonl
=====

Signature::

    * Library: wsock32
    * Return value: u_long

Parameters::

    ** u_long hostlong

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


htons
=====

Signature::

    * Library: wsock32
    * Return value: u_short

Parameters::

    ** u_short hostshort

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


inet_addr
=========

Signature::

    * Library: wsock32
    * Return value: unsigned long

Parameters::

    ** const char *cp

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


inet_ntoa
=========

Signature::

    * Library: wsock32
    * Return value: char FAR *

Parameters::

    ** struct in_addr in

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ioctlsocket
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** long cmd
    ** u_long *argp

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


listen
======

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** int backlog

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ntohl
=====

Signature::

    * Library: wsock32
    * Return value: u_long

Parameters::

    ** u_long netlong

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ntohs
=====

Signature::

    * Library: wsock32
    * Return value: u_short

Parameters::

    ** u_short netshort

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


shutdown
========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    ** SOCKET s
    ** int how

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


socket
======

Signature::

    * Library: wsock32
    * Return value: SOCKET

Parameters::

    ** int af
    ** int type
    ** int protocol

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AssignProcessToJobObject
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hJob
    ** HANDLE hProcess

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AttachThreadInput
=================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** DWORD idAttach
    ** DWORD idAttachTo
    ** BOOL fAttach

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AvQuerySystemResponsiveness
===========================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** HANDLE AvrtHandle
    ** PULONG SystemResponsivenessValue

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AvRevertMmThreadCharacteristics
===============================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** HANDLE AvrtHandle

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AvRtDeleteThreadOrderingGroup
=============================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** HANDLE Context

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AvRtJoinThreadOrderingGroup
===========================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** PHANDLE Context
    ** GUID *ThreadOrderingGuid
    ** BOOL Before

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AvRtLeaveThreadOrderingGroup
============================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** HANDLE Context

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AvRtWaitOnThreadOrderingGroup
=============================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** HANDLE Context

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AvSetMmMaxThreadCharacteristicsA
================================

Signature::

    * Library: avrt
    * Return value: HANDLE

Parameters::

    ** LPCSTR FirstTask
    ** LPCSTR SecondTask
    ** LPDWORD TaskIndex

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AvSetMmMaxThreadCharacteristicsW
================================

Signature::

    * Library: avrt
    * Return value: HANDLE

Parameters::

    ** LPCWSTR FirstTask
    ** LPCWSTR SecondTask
    ** LPDWORD TaskIndex

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AvSetMmThreadCharacteristicsA
=============================

Signature::

    * Library: avrt
    * Return value: HANDLE

Parameters::

    ** LPCSTR TaskName
    ** LPDWORD TaskIndex

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AvSetMmThreadCharacteristicsW
=============================

Signature::

    * Library: avrt
    * Return value: HANDLE

Parameters::

    ** LPCWSTR TaskName
    ** LPDWORD TaskIndex

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


AvSetMmThreadPriority
=====================

Signature::

    * Library: avrt
    * Return value: BOOL

Parameters::

    ** HANDLE AvrtHandle
    ** AVRT_PRIORITY Priority

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


BindIoCompletionCallback
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE FileHandle
    ** LPOVERLAPPED_COMPLETION_ROUTINE Function
    ** ULONG Flags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CallbackMayRunLong
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_CALLBACK_INSTANCE pci

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CancelThreadpoolIo
==================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_IO pio

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CloseThreadpool
===============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_POOL ptpp

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CloseThreadpoolCleanupGroup
===========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CLEANUP_GROUP ptpcg

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CloseThreadpoolCleanupGroupMembers
==================================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CLEANUP_GROUP ptpcg
    ** BOOL fCancelPendingCallbacks
    ** PVOID pvCleanupContext

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CloseThreadpoolIo
=================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_IO pio

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CloseThreadpoolTimer
====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_TIMER pti

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CloseThreadpoolWait
===================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WAIT pwa

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CloseThreadpoolWork
===================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WORK pwk

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ConvertFiberToThread
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ConvertThreadToFiber
====================

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** LPVOID lpParameter

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ConvertThreadToFiberEx
======================

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** LPVOID lpParameter
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateFiber
===========

Signature::

    * Library: kernel32
    * Return value: LPVOID

Parameters::

    ** SIZE_T dwStackSize
    ** LPFIBER_START_ROUTINE lpStartAddress
    ** LPVOID lpParameter

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateJobObjectA
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpJobAttributes
    ** LPCSTR lpName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateJobObjectW
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** LPSECURITY_ATTRIBUTES lpJobAttributes
    ** LPCWSTR lpName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateProcessAsUserA
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hToken
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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateProcessAsUserW
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hToken
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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Post::

    uint32_t pid = pid_from_thread_handle(ret);
    pipe("PROCESS:%d", pid);
    sleep_skip_disable();

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateThreadpool
================

Signature::

    * Library: kernel32
    * Return value: PTP_POOL

Parameters::

    ** PVOID reserved

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateThreadpoolCleanupGroup
============================

Signature::

    * Library: kernel32
    * Return value: PTP_CLEANUP_GROUP

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateThreadpoolTimer
=====================

Signature::

    * Library: kernel32
    * Return value: PTP_TIMER

Parameters::

    ** PTP_TIMER_CALLBACK pfnti
    ** PVOID pv
    ** PTP_CALLBACK_ENVIRON pcbe

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateThreadpoolWait
====================

Signature::

    * Library: kernel32
    * Return value: PTP_WAIT

Parameters::

    ** PTP_WAIT_CALLBACK pfnwa
    ** PVOID pv
    ** PTP_CALLBACK_ENVIRON pcbe

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


CreateThreadpoolWork
====================

Signature::

    * Library: kernel32
    * Return value: PTP_WORK

Parameters::

    ** PTP_WORK_CALLBACK pfnwk
    ** PVOID pv
    ** PTP_CALLBACK_ENVIRON pcbe

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DeleteFiber
===========

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPVOID lpFiber

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DeleteProcThreadAttributeList
=============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


DisassociateCurrentThreadFromCallback
=====================================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


EmptyWorkingSet
===============

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


EnumDeviceDrivers
=================

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** LPVOID *lpImageBase
    ** DWORD cb
    ** LPDWORD lpcbNeeded

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


EnumPageFilesA
==============

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** PENUM_PAGE_FILE_CALLBACKA pCallBackRoutine
    ** LPVOID pContext

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


EnumPageFilesW
==============

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** PENUM_PAGE_FILE_CALLBACKW pCallBackRoutine
    ** LPVOID pContext

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


EnumProcesses
=============

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** DWORD *lpidProcess
    ** DWORD cb
    ** LPDWORD lpcbNeeded

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ExitProcess
===========

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** UINT uExitCode

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ExitThread
==========

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** DWORD dwExitCode

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FlushProcessWriteBuffers
========================

Signature::

    * Library: kernel32
    * Return value: void

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FreeEnvironmentStringsA
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCH penv

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FreeEnvironmentStringsW
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPWCH penv

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


FreeLibraryWhenCallbackReturns
==============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** HMODULE mod

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetActiveProcessorCount
=======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** WORD GroupNumber

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetActiveProcessorGroupCount
============================

Signature::

    * Library: kernel32
    * Return value: WORD

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetCommandLineA
===============

Signature::

    * Library: kernel32
    * Return value: LPSTR

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetCommandLineW
===============

Signature::

    * Library: kernel32
    * Return value: LPWSTR

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetCurrentProcess
=================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetCurrentProcessId
===================

Signature::

    * Library: kernel32
    * Return value: DWORD

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetCurrentThread
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetDeviceDriverBaseNameA
========================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** LPVOID ImageBase
    ** LPSTR lpFilename
    ** DWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetDeviceDriverBaseNameW
========================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** LPVOID ImageBase
    ** LPWSTR lpBaseName
    ** DWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetDeviceDriverFileNameA
========================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** LPVOID ImageBase
    ** LPSTR lpFilename
    ** DWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetDeviceDriverFileNameW
========================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** LPVOID ImageBase
    ** LPWSTR lpFilename
    ** DWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetEnvironmentStrings
=====================

Signature::

    * Library: kernel32
    * Return value: LPCH

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetEnvironmentStringsW
======================

Signature::

    * Library: kernel32
    * Return value: LPWCH

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetEnvironmentVariableA
=======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCSTR lpName
    ** LPSTR lpBuffer
    ** DWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetEnvironmentVariableW
=======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** LPCWSTR lpName
    ** LPWSTR lpBuffer
    ** DWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetExitCodeProcess
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** LPDWORD lpExitCode

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetExitCodeThread
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** LPDWORD lpExitCode

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetGuiResources
===============

Signature::

    * Library: user32
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess
    ** DWORD uiFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetLogicalProcessorInformation
==============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PSYSTEM_LOGICAL_PROCESSOR_INFORMATION Buffer
    ** PDWORD ReturnedLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetLogicalProcessorInformationEx
================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType
    ** PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Buffer
    ** PDWORD ReturnedLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetMaximumProcessorCount
========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** WORD GroupNumber

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetMaximumProcessorGroupCount
=============================

Signature::

    * Library: kernel32
    * Return value: WORD

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetNumaAvailableMemoryNode
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UCHAR Node
    ** PULONGLONG AvailableBytes

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetNumaAvailableMemoryNodeEx
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** USHORT Node
    ** PULONGLONG AvailableBytes

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetNumaHighestNodeNumber
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PULONG HighestNodeNumber

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetNumaNodeNumberFromHandle
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hFile
    ** PUSHORT NodeNumber

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetNumaNodeProcessorMask
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UCHAR Node
    ** PULONGLONG ProcessorMask

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetNumaNodeProcessorMaskEx
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** USHORT Node
    ** PGROUP_AFFINITY ProcessorMask

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetNumaProcessorNode
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** UCHAR Processor
    ** PUCHAR NodeNumber

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetNumaProcessorNodeEx
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PPROCESSOR_NUMBER Processor
    ** PUSHORT NodeNumber

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetNumaProximityNode
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** ULONG ProximityId
    ** PUCHAR NodeNumber

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetNumaProximityNodeEx
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** ULONG ProximityId
    ** PUSHORT NodeNumber

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetPerformanceInfo
==================

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** PPERFORMANCE_INFORMATION pPerformanceInformation
    ** DWORD cb

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetPriorityClass
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcessAffinityMask
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PDWORD_PTR lpProcessAffinityMask
    ** PDWORD_PTR lpSystemAffinityMask

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcessGroupAffinity
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PUSHORT GroupCount
    ** PUSHORT GroupArray

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcessHandleCount
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PDWORD pdwHandleCount

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcessId
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE Process

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcessIdOfThread
====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE Thread

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcessImageFileNameA
========================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess
    ** LPSTR lpImageFileName
    ** DWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcessImageFileNameW
========================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess
    ** LPWSTR lpImageFileName
    ** DWORD nSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcessIoCounters
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PIO_COUNTERS lpIoCounters

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcessMemoryInfo
====================

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE Process
    ** PPROCESS_MEMORY_COUNTERS ppsmemCounters
    ** DWORD cb

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcessPriorityBoost
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PBOOL pDisablePriorityBoost

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcessShutdownParameters
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPDWORD lpdwLevel
    ** LPDWORD lpdwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcessVersion
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD ProcessId

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcessWorkingSetSize
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PSIZE_T lpMinimumWorkingSetSize
    ** PSIZE_T lpMaximumWorkingSetSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetProcessorSystemCycleTime
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** USHORT Group
    ** PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION Buffer
    ** PDWORD ReturnedLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetStartupInfoA
===============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSTARTUPINFOA lpStartupInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetStartupInfoW
===============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPSTARTUPINFOW lpStartupInfo

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetThreadGroupAffinity
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PGROUP_AFFINITY GroupAffinity

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetThreadIOPendingFlag
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PBOOL lpIOIsPending

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetThreadId
===========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE Thread

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetThreadIdealProcessorEx
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PPROCESSOR_NUMBER lpIdealProcessor

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetThreadPriority
=================

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    ** HANDLE hThread

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetThreadPriorityBoost
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PBOOL pDisablePriorityBoost

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetWsChanges
============

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PPSAPI_WS_WATCH_INFORMATION lpWatchInfo
    ** DWORD cb

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


GetWsChangesEx
==============

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PPSAPI_WS_WATCH_INFORMATION_EX lpWatchInfoEx
    ** PDWORD cb

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


InitializeProcessForWsWatch
===========================

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


IsImmersiveProcess
==================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


IsProcessInJob
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE ProcessHandle
    ** HANDLE JobHandle
    ** PBOOL Result

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


IsThreadAFiber
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


IsThreadpoolTimerSet
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_TIMER pti

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


IsWow64Message
==============

Signature::

    * Library: user32
    * Return value: BOOL

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


IsWow64Process
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PBOOL Wow64Process

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


LeaveCriticalSectionWhenCallbackReturns
=======================================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** PCRITICAL_SECTION pcs

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


NeedCurrentDirectoryForExePathA
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCSTR ExeName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


NeedCurrentDirectoryForExePathW
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR ExeName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenJobObjectA
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCSTR lpName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenJobObjectW
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** LPCWSTR lpName

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenProcess
===========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** DWORD dwProcessId

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


OpenThread
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    ** DWORD dwDesiredAccess
    ** BOOL bInheritHandle
    ** DWORD dwThreadId

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


Process32First
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot
    ** LPPROCESSENTRY32 lppe

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


Process32FirstW
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot
    ** LPPROCESSENTRY32W lppe

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


Process32Next
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot
    ** LPPROCESSENTRY32 lppe

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


Process32NextW
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hSnapshot
    ** LPPROCESSENTRY32W lppe

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueryIdleProcessorCycleTime
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PULONG BufferLength
    ** PULONG64 ProcessorIdleCycleTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueryIdleProcessorCycleTimeEx
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** USHORT Group
    ** PULONG BufferLength
    ** PULONG64 ProcessorIdleCycleTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueryProcessAffinityUpdateMode
==============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** LPDWORD lpdwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueryProcessCycleTime
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE ProcessHandle
    ** PULONG64 CycleTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueryThreadCycleTime
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE ThreadHandle
    ** PULONG64 CycleTime

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueryThreadpoolStackInformation
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_POOL ptpp
    ** PTP_POOL_STACK_INFORMATION ptpsi

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueryWorkingSet
===============

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PVOID pv
    ** DWORD cb

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueryWorkingSetEx
=================

Signature::

    * Library: psapi
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** PVOID pv
    ** DWORD cb

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


QueueUserWorkItem
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPTHREAD_START_ROUTINE Function
    ** PVOID Context
    ** ULONG Flags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ReleaseMutexWhenCallbackReturns
===============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** HANDLE mut

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ReleaseSemaphoreWhenCallbackReturns
===================================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** HANDLE sem
    ** DWORD crel

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


ResumeThread
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hThread

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetEnvironmentVariableW
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** LPCWSTR lpName
    ** LPCWSTR lpValue

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetEventWhenCallbackReturns
===========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_CALLBACK_INSTANCE pci
    ** HANDLE evt

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetPriorityClass
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** DWORD dwPriorityClass

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetProcessAffinityMask
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** DWORD_PTR dwProcessAffinityMask

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetProcessAffinityUpdateMode
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetProcessMitigationPolicy
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PROCESS_MITIGATION_POLICY MitigationPolicy
    ** PVOID lpBuffer
    ** SIZE_T dwLength

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetProcessPriorityBoost
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** BOOL bDisablePriorityBoost

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetProcessRestrictionExemption
==============================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** BOOL fEnableExemption

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetProcessShutdownParameters
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** DWORD dwLevel
    ** DWORD dwFlags

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetProcessWorkingSetSize
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** SIZE_T dwMinimumWorkingSetSize
    ** SIZE_T dwMaximumWorkingSetSize

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetThreadAffinityMask
=====================

Signature::

    * Library: kernel32
    * Return value: DWORD_PTR

Parameters::

    ** HANDLE hThread
    ** DWORD_PTR dwThreadAffinityMask

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetThreadGroupAffinity
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** const GROUP_AFFINITY *GroupAffinity
    ** PGROUP_AFFINITY PreviousGroupAffinity

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetThreadIdealProcessor
=======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hThread
    ** DWORD dwIdealProcessor

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetThreadIdealProcessorEx
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** PPROCESSOR_NUMBER lpIdealProcessor
    ** PPROCESSOR_NUMBER lpPreviousIdealProcessor

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetThreadPriority
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** int nPriority

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetThreadPriorityBoost
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hThread
    ** BOOL bDisablePriorityBoost

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetThreadStackGuarantee
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PULONG StackSizeInBytes

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetThreadpoolStackInformation
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_POOL ptpp
    ** PTP_POOL_STACK_INFORMATION ptpsi

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetThreadpoolThreadMaximum
==========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_POOL ptpp
    ** DWORD cthrdMost

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetThreadpoolThreadMinimum
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_POOL ptpp
    ** DWORD cthrdMic

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SetThreadpoolWait
=================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WAIT pwa
    ** HANDLE h
    ** PFILETIME pftTimeout

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


Sleep
=====

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** DWORD dwMilliseconds

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SleepEx
=======

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** DWORD dwMilliseconds
    ** BOOL bAlertable

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


StartThreadpoolIo
=================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_IO pio

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SubmitThreadpoolWork
====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WORK pwk

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SuspendThread
=============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hThread

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SwitchToFiber
=============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** LPVOID lpFiber

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


SwitchToThread
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


TerminateJobObject
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hJob
    ** UINT uExitCode

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


TerminateProcess
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** HANDLE hProcess
    ** UINT uExitCode

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif

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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


TrySubmitThreadpoolCallback
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    ** PTP_SIMPLE_CALLBACK pfns
    ** PVOID pv
    ** PTP_CALLBACK_ENVIRON pcbe

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


UserHandleGrantAccess
=====================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    ** HANDLE hUserHandle
    ** HANDLE hJob
    ** BOOL bGrant

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


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

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WaitForInputIdle
================

Signature::

    * Library: user32
    * Return value: DWORD

Parameters::

    ** HANDLE hProcess
    ** DWORD dwMilliseconds

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WaitForThreadpoolIoCallbacks
============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_IO pio
    ** BOOL fCancelPendingCallbacks

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WaitForThreadpoolTimerCallbacks
===============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_TIMER pti
    ** BOOL fCancelPendingCallbacks

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WaitForThreadpoolWaitCallbacks
==============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WAIT pwa
    ** BOOL fCancelPendingCallbacks

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


WaitForThreadpoolWorkCallbacks
==============================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    ** PTP_WORK pwk
    ** BOOL fCancelPendingCallbacks

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


Wow64SuspendThread
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    ** HANDLE hThread

Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


