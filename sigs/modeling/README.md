## Explanation of functions

  - File
    - https://msdn.microsoft.com/en-us/library/windows/desktop/aa364232(v=vs.85).aspx
    - https://msdn.microsoft.com/en-us/library/windows/desktop/aa363950(v=vs.85).aspx

  - Registry
    - https://msdn.microsoft.com/en-us/library/windows/desktop/ms724875(v=vs.85).aspx

  - Network
    - https://msdn.microsoft.com/en-us/library/windows/desktop/ff818516(v=vs.85).aspx#networking_and_internet
      - DNS Functions
      - Dynamic Host Configuration Protocol
      - HTTP Server API Version 1.0 Functions
      - HTTP Server API Version 2.0 Functions
      - IP Helper Functions
      - Network Management Functions
      - RPC Functions
      - WebSocket Protocol Component API Functions
      - Windows Firewall with Advanced Security Functions
      - Windows Networking Functions
      - WinHTTP Functions
      - WinINet Functions
      - Winsock Functions

  - Process
    - https://msdn.microsoft.com/en-us/library/windows/desktop/ms684847(v=vs.85).aspx
    - https://msdn.microsoft.com/en-us/library/windows/desktop/ms684894(v=vs.85).aspx

  - Synchronization
    - https://msdn.microsoft.com/en-us/library/windows/desktop/ms686360(v=vs.85).aspx

  - Object
    - https://msdn.microsoft.com/en-us/library/windows/desktop/ms724461(v=vs.85).aspx

  - System Info
    - https://msdn.microsoft.com/en-us/library/windows/desktop/ms724953(v=vs.85).aspx

  - Time
    - https://msdn.microsoft.com/en-us/library/windows/desktop/ms725473(v=vs.85).aspx
    - https://msdn.microsoft.com/en-us/library/windows/desktop/ms725476(v=vs.85).aspx

  - Service
    - https://msdn.microsoft.com/en-us/library/windows/desktop/ms685942(v=vs.85).aspx

  - DLL
    - https://msdn.microsoft.com/en-us/library/windows/desktop/ms682599(v=vs.85).aspx

  - Hook
    - https://msdn.microsoft.com/en-us/library/windows/desktop/ff468842(v=vs.85).aspx

  - Resource - not used at the moment
    - https://msdn.microsoft.com/en-us/library/windows/desktop/ff468902(v=vs.85).aspx

  - Cryptography - not used at the moment
    - https://msdn.microsoft.com/en-us/library/windows/desktop/aa380252(v=vs.85).aspx

  - Authorization - not used at the moment
    - https://msdn.microsoft.com/en-us/library/windows/desktop/aa375742(v=vs.85).aspx

# Functions removed

  - auth.txt
    - AuthzInitializeResourceManager
      - Reason: Minimum Windows 8
    - AuthzInitializeResourceManagerEx
      - Reason: Minimum Windows 8
    - AuthzInitializeRemoteResourceManager
      - Reason: Minimum Windows 8
    - AuthzRegisterCapChangeNotification
      - Reason: Minimum Windows 8
    - AuthzUnregisterCapChangeNotification
      - Reason: Minimum Windows 8

  - crypto.txt
    - CertIsStrongHashToSign
      - Reason: Minimum Windows 8
    - CertModifyCertificatesToTrust
      - Reason: Mingw-gcc doesn't have cryptdlg.h
    - CertSelectCertificate
      - Reason: Mingw-gcc doesn't have cryptdlg.h
    - CertSelectionGetSerializedBlob
      - Reason: Mingw-gcc doesn't have cryptdlg.h

  - dll.txt
    - These interfere with the monitor, causing it to crash:
      - GetModuleHandle
      - GetModuleHandleEx

  - file.txt
    - CreateFile2
      - Reason: Minimum Windows 8
    - CopyFile2
      - Reason: Minimum Windows 8
    - These interfere with the monitor, causing it to crash:
      - SearchPath
      - GetFullPathName
      - FindCloseChangeNotification

  - network.txt
    - These interfere with the monitor, causing it to crash:
      - GetAddrInfoW
      - getaddrinfo
      - InternetCreateUrl
      - GetAddrInfoEx
      - GetUrlCacheEntryInfo
      - GetUrlCacheEntryInfoEx
      - InternetGetConnectedState
      - InternetGetConnectedStateEx
      - CommitUrlCacheEntryA
      - CommitUrlCacheEntryW

  - process.txt
    - These interfere with the monitor, causing it to crash:
      - CreateJobObject
      - CreateProcessAsUser

    - Because these were not found in malware sources and are probably useless:
      - FlsAlloc
      - FlsFree
      - FlsGetValue
      - FlsSetValue

      - TlsAlloc
      - TlsFree
      - TlsGetValue
      - TlsSetValue

    - These slow the target program down
      - MsgWaitForMultipleObjects
      - MsgWaitForMultipleObjectsEx
      - GetCurrentProcessorNumber
      - GetCurrentProcessorNumberEx

  - registry.txt
    - These interfere with the monitor, causing it to crash:
      - RegQueryInfoKey
      - RegEnumKeyEx
      - RegLoadMUIString

  - service.txt
    - These interfere with the monitor, causing it to crash:
      - OpenSCManager

  - sync.txt
    - These interfere with the monitor, causing it to crash:
      - DeleteCriticalSection
      - EnterCriticalSection
      - InitializeCriticalSection
      - InitializeCriticalSectionAndSpinCount
      - InitializeCriticalSectionEx
      - LeaveCriticalSection
      - SetCriticalSectionSpinCount
      - TryEnterCriticalSection

      - CreateEvent
      - CreateEventEx
      - CreateMutex
      - CreateMutexEx
      - CreateSemaphore
      - CreateSemaphoreEx
      - CreateWaitableTimer
      - CreateWaitableTimerEx

    - These slow the target program down
      - AcquireSRWLockExclusive
      - AcquireSRWLockShared
      - InitializeSRWLock
      - ReleaseSRWLockExclusive
      - ReleaseSRWLockShared
      - TryAcquireSRWLockExclusive
      - TryAcquireSRWLockShared

      - InitOnceBeginInitialize
      - InitOnceComplete
      - InitOnceExecuteOnce
      - InitOnceInitialize
      - InitializeConditionVariable

      - AddIntegrityLabelToBoundaryDescriptor
      - AddSIDToBoundaryDescriptor
      - CreateBoundaryDescriptor
      - DeleteBoundaryDescriptor

      - InitializeSListHead
      - QueryDepthSList

      - RtlFirstEntrySList
      - RtlInitializeSListHead
      - RtlInterlockedFlushSList
      - RtlInterlockedPopEntrySList
      - RtlInterlockedPushEntrySList
      - RtlQueryDepthSList

      - InterlockedAdd
      - InterlockedAdd64
      - InterlockedAddAcquire
      - InterlockedAddAcquire64
      - InterlockedAddNoFence
      - InterlockedAddNoFence64
      - InterlockedAddRelease
      - InterlockedAddRelease64
      - InterlockedAnd
      - InterlockedAnd16
      - InterlockedAnd16Acquire
      - InterlockedAnd16NoFence
      - InterlockedAnd16Release
      - InterlockedAnd64
      - InterlockedAnd64Acquire
      - InterlockedAnd64NoFence
      - InterlockedAnd64Release
      - InterlockedAnd8
      - InterlockedAnd8Acquire
      - InterlockedAnd8NoFence
      - InterlockedAnd8Release
      - InterlockedAndAcquire
      - InterlockedAndNoFence
      - InterlockedAndRelease
      - InterlockedBitTestAndComplement
      - InterlockedBitTestAndComplement64
      - InterlockedBitTestAndReset
      - InterlockedBitTestAndReset64
      - InterlockedBitTestAndResetAcquire
      - InterlockedBitTestAndResetRelease
      - InterlockedBitTestAndSet
      - InterlockedBitTestAndSet64
      - InterlockedBitTestAndSetAcquire
      - InterlockedBitTestAndSetRelease
      - InterlockedCompare64Exchange128
      - InterlockedCompare64ExchangeAcquire128
      - InterlockedCompare64ExchangeRelease128
      - InterlockedCompareExchange
      - InterlockedCompareExchange128
      - InterlockedCompareExchange16
      - InterlockedCompareExchange16Acquire
      - InterlockedCompareExchange16NoFence
      - InterlockedCompareExchange16Release
      - InterlockedCompareExchange64
      - InterlockedCompareExchangeAcquire
      - InterlockedCompareExchangeAcquire64
      - InterlockedCompareExchangeNoFence
      - InterlockedCompareExchangeNoFence64
      - InterlockedCompareExchangePointer
      - InterlockedCompareExchangePointerAcquire
      - InterlockedCompareExchangePointerNoFence
      - InterlockedCompareExchangePointerRelease
      - InterlockedCompareExchangeRelease
      - InterlockedCompareExchangeRelease64
      - InterlockedDecrement
      - InterlockedDecrement16
      - InterlockedDecrement16Acquire
      - InterlockedDecrement16NoFence
      - InterlockedDecrement16Release
      - InterlockedDecrement64
      - InterlockedDecrementAcquire
      - InterlockedDecrementAcquire64
      - InterlockedDecrementNoFence
      - InterlockedDecrementNoFence64
      - InterlockedDecrementRelease
      - InterlockedDecrementRelease64
      - InterlockedExchange
      - InterlockedExchange16
      - InterlockedExchange16Acquire
      - InterlockedExchange16NoFence
      - InterlockedExchange64
      - InterlockedExchange8
      - InterlockedExchangeAcquire
      - InterlockedExchangeAcquire64
      - InterlockedExchangeAdd
      - InterlockedExchangeAdd64
      - InterlockedExchangeAddAcquire
      - InterlockedExchangeAddAcquire64
      - InterlockedExchangeAddNoFence
      - InterlockedExchangeAddNoFence64
      - InterlockedExchangeAddRelease
      - InterlockedExchangeAddRelease64
      - InterlockedExchangeNoFence
      - InterlockedExchangeNoFence64
      - InterlockedExchangePointer
      - InterlockedExchangePointerAcquire
      - InterlockedExchangePointerNoFence
      - InterlockedExchangeSubtract
      - InterlockedFlushSList
      - InterlockedIncrement
      - InterlockedIncrement16
      - InterlockedIncrement16Acquire
      - InterlockedIncrement16NoFence
      - InterlockedIncrement16Release
      - InterlockedIncrement64
      - InterlockedIncrementAcquire
      - InterlockedIncrementAcquire64
      - InterlockedIncrementNoFence
      - InterlockedIncrementNoFence64
      - InterlockedIncrementRelease
      - InterlockedIncrementRelease64
      - InterlockedOr
      - InterlockedOr16
      - InterlockedOr16Acquire
      - InterlockedOr16NoFence
      - InterlockedOr16Release
      - InterlockedOr64
      - InterlockedOr64Acquire
      - InterlockedOr64NoFence
      - InterlockedOr64Release
      - InterlockedOr8
      - InterlockedOr8Acquire
      - InterlockedOr8NoFence
      - InterlockedOr8Release
      - InterlockedOrAcquire
      - InterlockedOrNoFence
      - InterlockedOrRelease
      - InterlockedPopEntrySList
      - InterlockedPushEntrySList
      - InterlockedPushListSList
      - InterlockedPushListSListEx
      - InterlockedXor
      - InterlockedXor16
      - InterlockedXor16Acquire
      - InterlockedXor16NoFence
      - InterlockedXor16Release
      - InterlockedXor64
      - InterlockedXor64Acquire
      - InterlockedXor64NoFence
      - InterlockedXor64Release
      - InterlockedXor8
      - InterlockedXor8Acquire
      - InterlockedXor8NoFence
      - InterlockedXor8Release
      - InterlockedXorAcquire
      - InterlockedXorNoFence
      - InterlockedXorRelease

  - system-info.txt
    - These interfere with the monitor, causing it to crash:
      - ExpandEnvironmentStrings
      - GetSystemWindowsDirectory
      - GetSystemWow64Directory
      - GetSystemDirectory

  - time.txt
    - These interfere with the monitor, causing it to crash:
      - GetTimeFormat
      - FileTimeToDosDateTime

# Tests
  - Notepad.exe
    - Successful: No crash or early termination of target process
    - Saved many files to Desktop

  - Internet Explorer
    - Crashes before it can start up fully
    - Traces one process, spawns off another process and attempts to trace that as well.
      This is where it crashes
