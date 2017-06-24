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

  - Resource
    - https://msdn.microsoft.com/en-us/library/windows/desktop/ff468902(v=vs.85).aspx

  - Cryptography
    - https://msdn.microsoft.com/en-us/library/windows/desktop/aa380252(v=vs.85).aspx

  - Authorization
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

  - file.txt
    - CreateFile2
      - Reason: Minimum Windows 8

# Tests

  - Notepad: All files work except
    - process.txt slows execution down significantly
    - sync.txt prevents Notepad from running

  - Internet Explorer: All files works except
    - resource.txt causes it to crash after Internet Explorer has started
    - service.txt causes it to crash after Internet Explorer has started
    - I did not test process.txt and sync.txt like I did with Notepad, but since
      Internet Explorer does many more things than Notepad I assume I will
      see similar behavior.

