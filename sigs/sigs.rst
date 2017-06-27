Signature::

    * Calling convention: WINAPI
    * Category: none


AccessCheck
===========

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * HANDLE ClientToken
    * DWORD DesiredAccess
    * PGENERIC_MAPPING GenericMapping
    * PPRIVILEGE_SET PrivilegeSet
    * LPDWORD PrivilegeSetLength
    * LPDWORD GrantedAccess
    * LPBOOL AccessStatus


AccessCheckAndAuditAlarmA
=========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR SubsystemName
    * LPVOID HandleId
    * LPSTR ObjectTypeName
    * LPSTR ObjectName
    * PSECURITY_DESCRIPTOR SecurityDescriptor
    * DWORD DesiredAccess
    * PGENERIC_MAPPING GenericMapping
    * BOOL ObjectCreation
    * LPDWORD GrantedAccess
    * LPBOOL AccessStatus
    * LPBOOL pfGenerateOnClose


AccessCheckAndAuditAlarmW
=========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR SubsystemName
    * LPVOID HandleId
    * LPWSTR ObjectTypeName
    * LPWSTR ObjectName
    * PSECURITY_DESCRIPTOR SecurityDescriptor
    * DWORD DesiredAccess
    * PGENERIC_MAPPING GenericMapping
    * BOOL ObjectCreation
    * LPDWORD GrantedAccess
    * LPBOOL AccessStatus
    * LPBOOL pfGenerateOnClose


AccessCheckByType
=================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * PSID PrincipalSelfSid
    * HANDLE ClientToken
    * DWORD DesiredAccess
    * POBJECT_TYPE_LIST ObjectTypeList
    * DWORD ObjectTypeListLength
    * PGENERIC_MAPPING GenericMapping
    * PPRIVILEGE_SET PrivilegeSet
    * LPDWORD PrivilegeSetLength
    * LPDWORD GrantedAccess
    * LPBOOL AccessStatus


AccessCheckByTypeAndAuditAlarmA
===============================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR SubsystemName
    * LPVOID HandleId
    * LPCSTR ObjectTypeName
    * LPCSTR ObjectName
    * PSECURITY_DESCRIPTOR SecurityDescriptor
    * PSID PrincipalSelfSid
    * DWORD DesiredAccess
    * AUDIT_EVENT_TYPE AuditType
    * DWORD Flags
    * POBJECT_TYPE_LIST ObjectTypeList
    * DWORD ObjectTypeListLength
    * PGENERIC_MAPPING GenericMapping
    * BOOL ObjectCreation
    * LPDWORD GrantedAccess
    * LPBOOL AccessStatus
    * LPBOOL pfGenerateOnClose


AccessCheckByTypeAndAuditAlarmW
===============================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR SubsystemName
    * LPVOID HandleId
    * LPCWSTR ObjectTypeName
    * LPCWSTR ObjectName
    * PSECURITY_DESCRIPTOR SecurityDescriptor
    * PSID PrincipalSelfSid
    * DWORD DesiredAccess
    * AUDIT_EVENT_TYPE AuditType
    * DWORD Flags
    * POBJECT_TYPE_LIST ObjectTypeList
    * DWORD ObjectTypeListLength
    * PGENERIC_MAPPING GenericMapping
    * BOOL ObjectCreation
    * LPDWORD GrantedAccess
    * LPBOOL AccessStatus
    * LPBOOL pfGenerateOnClose


AccessCheckByTypeResultList
===========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * PSID PrincipalSelfSid
    * HANDLE ClientToken
    * DWORD DesiredAccess
    * POBJECT_TYPE_LIST ObjectTypeList
    * DWORD ObjectTypeListLength
    * PGENERIC_MAPPING GenericMapping
    * PPRIVILEGE_SET PrivilegeSet
    * LPDWORD PrivilegeSetLength
    * LPDWORD GrantedAccessList
    * LPDWORD AccessStatusList


AccessCheckByTypeResultListAndAuditAlarmA
=========================================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR SubsystemName
    * LPVOID HandleId
    * LPCSTR ObjectTypeName
    * LPCSTR ObjectName
    * PSECURITY_DESCRIPTOR SecurityDescriptor
    * PSID PrincipalSelfSid
    * DWORD DesiredAccess
    * AUDIT_EVENT_TYPE AuditType
    * DWORD Flags
    * POBJECT_TYPE_LIST ObjectTypeList
    * DWORD ObjectTypeListLength
    * PGENERIC_MAPPING GenericMapping
    * BOOL ObjectCreation
    * LPDWORD GrantedAccess
    * LPDWORD AccessStatusList
    * LPBOOL pfGenerateOnClose


AccessCheckByTypeResultListAndAuditAlarmW
=========================================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR SubsystemName
    * LPVOID HandleId
    * LPCWSTR ObjectTypeName
    * LPCWSTR ObjectName
    * PSECURITY_DESCRIPTOR SecurityDescriptor
    * PSID PrincipalSelfSid
    * DWORD DesiredAccess
    * AUDIT_EVENT_TYPE AuditType
    * DWORD Flags
    * POBJECT_TYPE_LIST ObjectTypeList
    * DWORD ObjectTypeListLength
    * PGENERIC_MAPPING GenericMapping
    * BOOL ObjectCreation
    * LPDWORD GrantedAccessList
    * LPDWORD AccessStatusList
    * LPBOOL pfGenerateOnClose


AccessCheckByTypeResultListAndAuditAlarmByHandleA
=================================================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR SubsystemName
    * LPVOID HandleId
    * HANDLE ClientToken
    * LPCSTR ObjectTypeName
    * LPCSTR ObjectName
    * PSECURITY_DESCRIPTOR SecurityDescriptor
    * PSID PrincipalSelfSid
    * DWORD DesiredAccess
    * AUDIT_EVENT_TYPE AuditType
    * DWORD Flags
    * POBJECT_TYPE_LIST ObjectTypeList
    * DWORD ObjectTypeListLength
    * PGENERIC_MAPPING GenericMapping
    * BOOL ObjectCreation
    * LPDWORD GrantedAccess
    * LPDWORD AccessStatusList
    * LPBOOL pfGenerateOnClose


AccessCheckByTypeResultListAndAuditAlarmByHandleW
=================================================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR SubsystemName
    * LPVOID HandleId
    * HANDLE ClientToken
    * LPCWSTR ObjectTypeName
    * LPCWSTR ObjectName
    * PSECURITY_DESCRIPTOR SecurityDescriptor
    * PSID PrincipalSelfSid
    * DWORD DesiredAccess
    * AUDIT_EVENT_TYPE AuditType
    * DWORD Flags
    * POBJECT_TYPE_LIST ObjectTypeList
    * DWORD ObjectTypeListLength
    * PGENERIC_MAPPING GenericMapping
    * BOOL ObjectCreation
    * LPDWORD GrantedAccessList
    * LPDWORD AccessStatusList
    * LPBOOL pfGenerateOnClose


AddAccessAllowedAce
===================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD dwAceRevision
    * DWORD AccessMask
    * PSID pSid


AddAccessAllowedAceEx
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD dwAceRevision
    * DWORD AceFlags
    * DWORD AccessMask
    * PSID pSid


AddAccessAllowedObjectAce
=========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD dwAceRevision
    * DWORD AceFlags
    * DWORD AccessMask
    * GUID *ObjectTypeGuid
    * GUID *InheritedObjectTypeGuid
    * PSID pSid


AddAccessDeniedAce
==================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD dwAceRevision
    * DWORD AccessMask
    * PSID pSid


AddAccessDeniedAceEx
====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD dwAceRevision
    * DWORD AceFlags
    * DWORD AccessMask
    * PSID pSid


AddAccessDeniedObjectAce
========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD dwAceRevision
    * DWORD AceFlags
    * DWORD AccessMask
    * GUID *ObjectTypeGuid
    * GUID *InheritedObjectTypeGuid
    * PSID pSid


AddAce
======

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD dwAceRevision
    * DWORD dwStartingAceIndex
    * LPVOID pAceList
    * DWORD nAceListLength


AddAuditAccessAce
=================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD dwAceRevision
    * DWORD dwAccessMask
    * PSID pSid
    * BOOL bAuditSuccess
    * BOOL bAuditFailure


AddAuditAccessAceEx
===================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD dwAceRevision
    * DWORD AceFlags
    * DWORD dwAccessMask
    * PSID pSid
    * BOOL bAuditSuccess
    * BOOL bAuditFailure


AddAuditAccessObjectAce
=======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD dwAceRevision
    * DWORD AceFlags
    * DWORD AccessMask
    * GUID *ObjectTypeGuid
    * GUID *InheritedObjectTypeGuid
    * PSID pSid
    * BOOL bAuditSuccess
    * BOOL bAuditFailure


AddConditionalAce
=================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD dwAceRevision
    * DWORD AceFlags
    * UCHAR AceType
    * DWORD AccessMask
    * PSID pSid
    * PWCHAR ConditionStr
    * DWORD *ReturnLength


AddMandatoryAce
===============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD dwAceRevision
    * DWORD AceFlags
    * DWORD MandatoryPolicy
    * PSID pLabelSid


AdjustTokenGroups
=================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE TokenHandle
    * BOOL ResetToDefault
    * PTOKEN_GROUPS NewState
    * DWORD BufferLength
    * PTOKEN_GROUPS PreviousState
    * PDWORD ReturnLength


AdjustTokenPrivileges
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE TokenHandle
    * BOOL DisableAllPrivileges
    * PTOKEN_PRIVILEGES NewState
    * DWORD BufferLength
    * PTOKEN_PRIVILEGES PreviousState
    * PDWORD ReturnLength


AllocateAndInitializeSid
========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority
    * BYTE nSubAuthorityCount
    * DWORD nSubAuthority0
    * DWORD nSubAuthority1
    * DWORD nSubAuthority2
    * DWORD nSubAuthority3
    * DWORD nSubAuthority4
    * DWORD nSubAuthority5
    * DWORD nSubAuthority6
    * DWORD nSubAuthority7
    * PSID *pSid


AllocateLocallyUniqueId
=======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PLUID Luid


AreAllAccessesGranted
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * DWORD GrantedAccess
    * DWORD DesiredAccess


AreAnyAccessesGranted
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * DWORD GrantedAccess
    * DWORD DesiredAccess


AuthzAccessCheck
================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * DWORD Flags
    * AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClientContext
    * PAUTHZ_ACCESS_REQUEST pRequest
    * AUTHZ_AUDIT_EVENT_HANDLE hAuditEvent
    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * PSECURITY_DESCRIPTOR *OptionalSecurityDescriptorArray
    * DWORD OptionalSecurityDescriptorCount
    * PAUTHZ_ACCESS_REPLY pReply
    * PAUTHZ_ACCESS_CHECK_RESULTS_HANDLE phAccessCheckResults


AuthzAddSidsToContext
=====================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClientContext
    * PSID_AND_ATTRIBUTES Sids
    * DWORD SidCount
    * PSID_AND_ATTRIBUTES RestrictedSids
    * DWORD RestrictedSidCount
    * PAUTHZ_CLIENT_CONTEXT_HANDLE phNewAuthzClientContext


AuthzCachedAccessCheck
======================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * DWORD Flags
    * AUTHZ_ACCESS_CHECK_RESULTS_HANDLE hAccessCheckResults
    * PAUTHZ_ACCESS_REQUEST pRequest
    * AUTHZ_AUDIT_EVENT_HANDLE hAuditEvent
    * PAUTHZ_ACCESS_REPLY pReply


AuthzEnumerateSecurityEventSources
==================================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * DWORD dwFlags
    * PAUTHZ_SOURCE_SCHEMA_REGISTRATION Buffer
    * PDWORD pdwCount
    * PDWORD pdwLength


AuthzFreeAuditEvent
===================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * AUTHZ_AUDIT_EVENT_HANDLE hAuditEvent


AuthzFreeContext
================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClientContext


AuthzFreeHandle
===============

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * AUTHZ_ACCESS_CHECK_RESULTS_HANDLE hAccessCheckResults


AuthzFreeResourceManager
========================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * AUTHZ_RESOURCE_MANAGER_HANDLE hAuthzResourceManager


AuthzGetInformationFromContext
==============================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClientContext
    * AUTHZ_CONTEXT_INFORMATION_CLASS InfoClass
    * DWORD BufferSize
    * PDWORD pSizeRequired
    * PVOID Buffer


AuthzInitializeContextFromAuthzContext
======================================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * DWORD Flags
    * AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClientContext
    * PLARGE_INTEGER pExpirationTime
    * LUID Identifier
    * PVOID DynamicGroupArgs
    * PAUTHZ_CLIENT_CONTEXT_HANDLE phNewAuthzClientContext


AuthzInitializeContextFromSid
=============================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * DWORD Flags
    * PSID UserSid
    * AUTHZ_RESOURCE_MANAGER_HANDLE hAuthzResourceManager
    * PLARGE_INTEGER pExpirationTime
    * LUID Identifier
    * PVOID DynamicGroupArgs
    * PAUTHZ_CLIENT_CONTEXT_HANDLE phAuthzClientContext


AuthzInitializeContextFromToken
===============================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * DWORD Flags
    * HANDLE TokenHandle
    * AUTHZ_RESOURCE_MANAGER_HANDLE hAuthzResourceManager
    * PLARGE_INTEGER pExpirationTime
    * LUID Identifier
    * PVOID DynamicGroupArgs
    * PAUTHZ_CLIENT_CONTEXT_HANDLE phAuthzClientContext


AuthzInstallSecurityEventSource
===============================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * DWORD dwFlags
    * PAUTHZ_SOURCE_SCHEMA_REGISTRATION pRegistration


AuthzOpenObjectAudit
====================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * DWORD Flags
    * AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClientContext
    * PAUTHZ_ACCESS_REQUEST pRequest
    * AUTHZ_AUDIT_EVENT_HANDLE hAuditEvent
    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * PSECURITY_DESCRIPTOR *OptionalSecurityDescriptorArray
    * DWORD OptionalSecurityDescriptorCount
    * PAUTHZ_ACCESS_REPLY pReply


AuthzRegisterSecurityEventSource
================================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * DWORD dwFlags
    * PCWSTR szEventSourceName
    * PAUTHZ_SECURITY_EVENT_PROVIDER_HANDLE phEventProvider


AuthzReportSecurityEventFromParams
==================================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * DWORD dwFlags
    * AUTHZ_SECURITY_EVENT_PROVIDER_HANDLE hEventProvider
    * DWORD dwAuditId
    * PSID pUserSid
    * PAUDIT_PARAMS pParams


AuthzUninstallSecurityEventSource
=================================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * DWORD dwFlags
    * PCWSTR szEventSourceName


AuthzUnregisterSecurityEventSource
==================================

Signature::

    * Library: authz
    * Return value: BOOL

Parameters::

    * DWORD dwFlags
    * PAUTHZ_SECURITY_EVENT_PROVIDER_HANDLE phEventProvider


BuildExplicitAccessWithNameA
============================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PEXPLICIT_ACCESS_A pExplicitAccess
    * LPSTR pTrusteeName
    * DWORD AccessPermissions
    * ACCESS_MODE AccessMode
    * DWORD Inheritance


BuildExplicitAccessWithNameW
============================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PEXPLICIT_ACCESS_W pExplicitAccess
    * LPWSTR pTrusteeName
    * DWORD AccessPermissions
    * ACCESS_MODE AccessMode
    * DWORD Inheritance


BuildImpersonateExplicitAccessWithNameA
=======================================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PEXPLICIT_ACCESS_A pExplicitAccess
    * LPSTR pTrusteeName
    * PTRUSTEE_A pTrustee
    * DWORD AccessPermissions
    * ACCESS_MODE AccessMode
    * DWORD Inheritance


BuildImpersonateExplicitAccessWithNameW
=======================================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PEXPLICIT_ACCESS_W pExplicitAccess
    * LPWSTR pTrusteeName
    * PTRUSTEE_W pTrustee
    * DWORD AccessPermissions
    * ACCESS_MODE AccessMode
    * DWORD Inheritance


BuildImpersonateTrusteeA
========================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PTRUSTEE_A pTrustee
    * PTRUSTEE_A pImpersonateTrustee


BuildImpersonateTrusteeW
========================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PTRUSTEE_W pTrustee
    * PTRUSTEE_W pImpersonateTrustee


BuildSecurityDescriptorA
========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PTRUSTEE_A pOwner
    * PTRUSTEE_A pGroup
    * ULONG cCountOfAccessEntries
    * PEXPLICIT_ACCESS_A pListOfAccessEntries
    * ULONG cCountOfAuditEntries
    * PEXPLICIT_ACCESS_A pListOfAuditEntries
    * PSECURITY_DESCRIPTOR pOldSD
    * PULONG pSizeNewSD
    * PSECURITY_DESCRIPTOR *pNewSD


BuildSecurityDescriptorW
========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PTRUSTEE_W pOwner
    * PTRUSTEE_W pGroup
    * ULONG cCountOfAccessEntries
    * PEXPLICIT_ACCESS_W pListOfAccessEntries
    * ULONG cCountOfAuditEntries
    * PEXPLICIT_ACCESS_W pListOfAuditEntries
    * PSECURITY_DESCRIPTOR pOldSD
    * PULONG pSizeNewSD
    * PSECURITY_DESCRIPTOR *pNewSD


BuildTrusteeWithNameA
=====================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PTRUSTEE_A pTrustee
    * LPSTR pName


BuildTrusteeWithNameW
=====================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PTRUSTEE_W pTrustee
    * LPWSTR pName


BuildTrusteeWithObjectsAndNameA
===============================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PTRUSTEE_A pTrustee
    * POBJECTS_AND_NAME_A pObjName
    * SE_OBJECT_TYPE ObjectType
    * LPSTR ObjectTypeName
    * LPSTR InheritedObjectTypeName
    * LPSTR Name


BuildTrusteeWithObjectsAndNameW
===============================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PTRUSTEE_W pTrustee
    * POBJECTS_AND_NAME_W pObjName
    * SE_OBJECT_TYPE ObjectType
    * LPWSTR ObjectTypeName
    * LPWSTR InheritedObjectTypeName
    * LPWSTR Name


BuildTrusteeWithObjectsAndSidA
==============================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PTRUSTEE_A pTrustee
    * POBJECTS_AND_SID pObjSid
    * GUID *pObjectGuid
    * GUID *pInheritedObjectGuid
    * PSID pSid


BuildTrusteeWithObjectsAndSidW
==============================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PTRUSTEE_W pTrustee
    * POBJECTS_AND_SID pObjSid
    * GUID *pObjectGuid
    * GUID *pInheritedObjectGuid
    * PSID pSid


BuildTrusteeWithSidA
====================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PTRUSTEE_A pTrustee
    * PSID pSid


BuildTrusteeWithSidW
====================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PTRUSTEE_W pTrustee
    * PSID pSid


CheckTokenMembership
====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE TokenHandle
    * PSID SidToCheck
    * PBOOL IsMember


ConvertToAutoInheritPrivateObjectSecurity
=========================================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR ParentDescriptor
    * PSECURITY_DESCRIPTOR CurrentSecurityDescriptor
    * PSECURITY_DESCRIPTOR *NewSecurityDescriptor
    * GUID *ObjectType
    * BOOLEAN IsDirectoryObject
    * PGENERIC_MAPPING GenericMapping


CopySid
=======

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * DWORD nDestinationSidLength
    * PSID pDestinationSid
    * PSID pSourceSid


CreatePrivateObjectSecurity
===========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR ParentDescriptor
    * PSECURITY_DESCRIPTOR CreatorDescriptor
    * PSECURITY_DESCRIPTOR *NewDescriptor
    * BOOL IsDirectoryObject
    * HANDLE Token
    * PGENERIC_MAPPING GenericMapping


CreatePrivateObjectSecurityEx
=============================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR ParentDescriptor
    * PSECURITY_DESCRIPTOR CreatorDescriptor
    * PSECURITY_DESCRIPTOR *NewDescriptor
    * GUID *ObjectType
    * BOOL IsContainerObject
    * ULONG AutoInheritFlags
    * HANDLE Token
    * PGENERIC_MAPPING GenericMapping


CreatePrivateObjectSecurityWithMultipleInheritance
==================================================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR ParentDescriptor
    * PSECURITY_DESCRIPTOR CreatorDescriptor
    * PSECURITY_DESCRIPTOR *NewDescriptor
    * GUID **ObjectTypes
    * ULONG GuidCount
    * BOOL IsContainerObject
    * ULONG AutoInheritFlags
    * HANDLE Token
    * PGENERIC_MAPPING GenericMapping


CreateRestrictedToken
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE ExistingTokenHandle
    * DWORD Flags
    * DWORD DisableSidCount
    * PSID_AND_ATTRIBUTES SidsToDisable
    * DWORD DeletePrivilegeCount
    * PLUID_AND_ATTRIBUTES PrivilegesToDelete
    * DWORD RestrictedSidCount
    * PSID_AND_ATTRIBUTES SidsToRestrict
    * PHANDLE NewTokenHandle


CreateWellKnownSid
==================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * WELL_KNOWN_SID_TYPE WellKnownSidType
    * PSID DomainSid
    * PSID pSid
    * DWORD *cbSid


DeleteAce
=========

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD dwAceIndex


DestroyPrivateObjectSecurity
============================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR *ObjectDescriptor


DuplicateToken
==============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE ExistingTokenHandle
    * SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
    * PHANDLE DuplicateTokenHandle


DuplicateTokenEx
================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE hExistingToken
    * DWORD dwDesiredAccess
    * LPSECURITY_ATTRIBUTES lpTokenAttributes
    * SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
    * TOKEN_TYPE TokenType
    * PHANDLE phNewToken


EqualDomainSid
==============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSID pSid1
    * PSID pSid2
    * BOOL *pfEqual


EqualPrefixSid
==============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSID pSid1
    * PSID pSid2


EqualSid
========

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSID pSid1
    * PSID pSid2


FindFirstFreeAce
================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * LPVOID *pAce


FreeInheritedFromArray
======================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PINHERITED_FROMW pInheritArray
    * USHORT AceCnt
    * PFN_OBJECT_MGR_FUNCTS pfnArray


FreeSid
=======

Signature::

    * Library: advapi32
    * Return value: PVOID

Parameters::

    * PSID pSid


GetAce
======

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD dwAceIndex
    * LPVOID *pAce


GetAclInformation
=================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * LPVOID pAclInformation
    * DWORD nAclInformationLength
    * ACL_INFORMATION_CLASS dwAclInformationClass


GetAuditedPermissionsFromAclA
=============================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PACL pacl
    * PTRUSTEE_A pTrustee
    * PACCESS_MASK pSuccessfulAuditedRights
    * PACCESS_MASK pFailedAuditRights


GetAuditedPermissionsFromAclW
=============================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PACL pacl
    * PTRUSTEE_W pTrustee
    * PACCESS_MASK pSuccessfulAuditedRights
    * PACCESS_MASK pFailedAuditRights


GetEffectiveRightsFromAclA
==========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PACL pacl
    * PTRUSTEE_A pTrustee
    * PACCESS_MASK pAccessRights


GetEffectiveRightsFromAclW
==========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PACL pacl
    * PTRUSTEE_W pTrustee
    * PACCESS_MASK pAccessRights


GetExplicitEntriesFromAclA
==========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PACL pacl
    * PULONG pcCountOfExplicitEntries
    * PEXPLICIT_ACCESS_A *pListOfExplicitEntries


GetExplicitEntriesFromAclW
==========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PACL pacl
    * PULONG pcCountOfExplicitEntries
    * PEXPLICIT_ACCESS_W *pListOfExplicitEntries


GetFileSecurityA
================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR lpFileName
    * SECURITY_INFORMATION RequestedInformation
    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * DWORD nLength
    * LPDWORD lpnLengthNeeded


GetFileSecurityW
================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName
    * SECURITY_INFORMATION RequestedInformation
    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * DWORD nLength
    * LPDWORD lpnLengthNeeded


GetInheritanceSourceA
=====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPSTR pObjectName
    * SE_OBJECT_TYPE ObjectType
    * SECURITY_INFORMATION SecurityInfo
    * BOOL Container
    * GUID **pObjectClassGuids
    * DWORD GuidCount
    * PACL pAcl
    * PFN_OBJECT_MGR_FUNCTS pfnArray
    * PGENERIC_MAPPING pGenericMapping
    * PINHERITED_FROMA pInheritArray


GetInheritanceSourceW
=====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPWSTR pObjectName
    * SE_OBJECT_TYPE ObjectType
    * SECURITY_INFORMATION SecurityInfo
    * BOOL Container
    * GUID **pObjectClassGuids
    * DWORD GuidCount
    * PACL pAcl
    * PFN_OBJECT_MGR_FUNCTS pfnArray
    * PGENERIC_MAPPING pGenericMapping
    * PINHERITED_FROMW pInheritArray


GetKernelObjectSecurity
=======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE Handle
    * SECURITY_INFORMATION RequestedInformation
    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * DWORD nLength
    * LPDWORD lpnLengthNeeded


GetLengthSid
============

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PSID pSid


GetMultipleTrusteeA
===================

Signature::

    * Library: advapi32
    * Return value: PTRUSTEE_A

Parameters::

    * PTRUSTEE_A pTrustee


GetMultipleTrusteeW
===================

Signature::

    * Library: advapi32
    * Return value: PTRUSTEE_W

Parameters::

    * PTRUSTEE_W pTrustee


GetMultipleTrusteeOperationA
============================

Signature::

    * Library: advapi32
    * Return value: MULTIPLE_TRUSTEE_OPERATION

Parameters::

    * PTRUSTEE_A pTrustee


GetMultipleTrusteeOperationW
============================

Signature::

    * Library: advapi32
    * Return value: MULTIPLE_TRUSTEE_OPERATION

Parameters::

    * PTRUSTEE_W pTrustee


GetNamedSecurityInfoA
=====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPCSTR pObjectName
    * SE_OBJECT_TYPE ObjectType
    * SECURITY_INFORMATION SecurityInfo
    * PSID *ppsidOwner
    * PSID *ppsidGroup
    * PACL *ppDacl
    * PACL *ppSacl
    * PSECURITY_DESCRIPTOR *ppSecurityDescriptor


GetNamedSecurityInfoW
=====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPCWSTR pObjectName
    * SE_OBJECT_TYPE ObjectType
    * SECURITY_INFORMATION SecurityInfo
    * PSID *ppsidOwner
    * PSID *ppsidGroup
    * PACL *ppDacl
    * PACL *ppSacl
    * PSECURITY_DESCRIPTOR *ppSecurityDescriptor


GetPrivateObjectSecurity
========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR ObjectDescriptor
    * SECURITY_INFORMATION SecurityInformation
    * PSECURITY_DESCRIPTOR ResultantDescriptor
    * DWORD DescriptorLength
    * PDWORD ReturnLength


GetSecurityDescriptorControl
============================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * PSECURITY_DESCRIPTOR_CONTROL pControl
    * LPDWORD lpdwRevision


GetSecurityDescriptorDacl
=========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * LPBOOL lpbDaclPresent
    * PACL *pDacl
    * LPBOOL lpbDaclDefaulted


GetSecurityDescriptorGroup
==========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * PSID *pGroup
    * LPBOOL lpbGroupDefaulted


GetSecurityDescriptorLength
===========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor


GetSecurityDescriptorOwner
==========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * PSID *pOwner
    * LPBOOL lpbOwnerDefaulted


GetSecurityDescriptorRMControl
==============================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PSECURITY_DESCRIPTOR SecurityDescriptor
    * PUCHAR RMControl


GetSecurityDescriptorSacl
=========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * LPBOOL lpbSaclPresent
    * PACL *pSacl
    * LPBOOL lpbSaclDefaulted


GetSecurityInfo
===============

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * HANDLE handle
    * SE_OBJECT_TYPE ObjectType
    * SECURITY_INFORMATION SecurityInfo
    * PSID *ppsidOwner
    * PSID *ppsidGroup
    * PACL *ppDacl
    * PACL *ppSacl
    * PSECURITY_DESCRIPTOR *ppSecurityDescriptor


GetSidIdentifierAuthority
=========================

Signature::

    * Library: advapi32
    * Return value: PSID_IDENTIFIER_AUTHORITY

Parameters::

    * PSID pSid


GetSidLengthRequired
====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * UCHAR nSubAuthorityCount


GetSidSubAuthority
==================

Signature::

    * Library: advapi32
    * Return value: PDWORD

Parameters::

    * PSID pSid
    * DWORD nSubAuthority


GetSidSubAuthorityCount
=======================

Signature::

    * Library: advapi32
    * Return value: PUCHAR

Parameters::

    * PSID pSid


GetTokenInformation
===================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE TokenHandle
    * TOKEN_INFORMATION_CLASS TokenInformationClass
    * LPVOID TokenInformation
    * DWORD TokenInformationLength
    * PDWORD ReturnLength


GetTrusteeFormA
===============

Signature::

    * Library: advapi32
    * Return value: TRUSTEE_FORM

Parameters::

    * PTRUSTEE_A pTrustee


GetTrusteeFormW
===============

Signature::

    * Library: advapi32
    * Return value: TRUSTEE_FORM

Parameters::

    * PTRUSTEE_W pTrustee


GetTrusteeNameA
===============

Signature::

    * Library: advapi32
    * Return value: LPSTR

Parameters::

    * PTRUSTEE_A pTrustee


GetTrusteeNameW
===============

Signature::

    * Library: advapi32
    * Return value: LPWSTR

Parameters::

    * PTRUSTEE_W pTrustee


GetTrusteeTypeA
===============

Signature::

    * Library: advapi32
    * Return value: TRUSTEE_TYPE

Parameters::

    * PTRUSTEE_A pTrustee


GetTrusteeTypeW
===============

Signature::

    * Library: advapi32
    * Return value: TRUSTEE_TYPE

Parameters::

    * PTRUSTEE_W pTrustee


GetUserObjectSecurity
=====================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    * HANDLE hObj
    * PSECURITY_INFORMATION pSIRequested
    * PSECURITY_DESCRIPTOR pSID
    * DWORD nLength
    * LPDWORD lpnLengthNeeded


GetWindowsAccountDomainSid
==========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSID pSid
    * PSID pDomainSid
    * DWORD *cbDomainSid


ImpersonateAnonymousToken
=========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE ThreadHandle


ImpersonateLoggedOnUser
=======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE hToken


ImpersonateNamedPipeClient
==========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE hNamedPipe


ImpersonateSelf
===============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * SECURITY_IMPERSONATION_LEVEL ImpersonationLevel


InitializeAcl
=============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * DWORD nAclLength
    * DWORD dwAclRevision


InitializeSecurityDescriptor
============================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * DWORD dwRevision


InitializeSid
=============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSID Sid
    * PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority
    * BYTE nSubAuthorityCount


IsTokenRestricted
=================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE TokenHandle


IsValidAcl
==========

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl


IsValidSecurityDescriptor
=========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor


IsValidSid
==========

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSID pSid


IsWellKnownSid
==============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSID pSid
    * WELL_KNOWN_SID_TYPE WellKnownSidType


LookupAccountNameA
==================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR lpSystemName
    * LPCSTR lpAccountName
    * PSID Sid
    * LPDWORD cbSid
    * LPSTR ReferencedDomainName
    * LPDWORD cchReferencedDomainName
    * PSID_NAME_USE peUse


LookupAccountNameW
==================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpSystemName
    * LPCWSTR lpAccountName
    * PSID Sid
    * LPDWORD cbSid
    * LPWSTR ReferencedDomainName
    * LPDWORD cchReferencedDomainName
    * PSID_NAME_USE peUse


LookupAccountSidA
=================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR lpSystemName
    * PSID Sid
    * LPSTR Name
    * LPDWORD cchName
    * LPSTR ReferencedDomainName
    * LPDWORD cchReferencedDomainName
    * PSID_NAME_USE peUse


LookupAccountSidW
=================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpSystemName
    * PSID Sid
    * LPWSTR Name
    * LPDWORD cchName
    * LPWSTR ReferencedDomainName
    * LPDWORD cchReferencedDomainName
    * PSID_NAME_USE peUse


LookupAccountSidLocalA
======================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    * PSID Sid
    * LPSTR Name
    * LPDWORD cchName
    * LPSTR ReferencedDomainName
    * LPDWORD cchReferencedDomainName
    * PSID_NAME_USE peUse


LookupAccountSidLocalW
======================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    * PSID Sid
    * LPWSTR Name
    * LPDWORD cchName
    * LPWSTR ReferencedDomainName
    * LPDWORD cchReferencedDomainName
    * PSID_NAME_USE peUse


LookupPrivilegeDisplayNameA
===========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR lpSystemName
    * LPCSTR lpName
    * LPSTR lpDisplayName
    * LPDWORD cchDisplayName
    * LPDWORD lpLanguageId


LookupPrivilegeDisplayNameW
===========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpSystemName
    * LPCWSTR lpName
    * LPWSTR lpDisplayName
    * LPDWORD cchDisplayName
    * LPDWORD lpLanguageId


LookupPrivilegeNameA
====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR lpSystemName
    * PLUID lpLuid
    * LPSTR lpName
    * LPDWORD cchName


LookupPrivilegeNameW
====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpSystemName
    * PLUID lpLuid
    * LPWSTR lpName
    * LPDWORD cchName


LookupPrivilegeValueA
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR lpSystemName
    * LPCSTR lpName
    * PLUID lpLuid


LookupPrivilegeValueW
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpSystemName
    * LPCWSTR lpName
    * PLUID lpLuid


LookupSecurityDescriptorPartsA
==============================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PTRUSTEE_A *ppOwner
    * PTRUSTEE_A *ppGroup
    * PULONG pcCountOfAccessEntries
    * PEXPLICIT_ACCESS_A *ppListOfAccessEntries
    * PULONG pcCountOfAuditEntries
    * PEXPLICIT_ACCESS_A *ppListOfAuditEntries
    * PSECURITY_DESCRIPTOR pSD


LookupSecurityDescriptorPartsW
==============================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PTRUSTEE_W *ppOwner
    * PTRUSTEE_W *ppGroup
    * PULONG pcCountOfAccessEntries
    * PEXPLICIT_ACCESS_W *ppListOfAccessEntries
    * PULONG pcCountOfAuditEntries
    * PEXPLICIT_ACCESS_W *ppListOfAuditEntries
    * PSECURITY_DESCRIPTOR pSD


MakeAbsoluteSD
==============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor
    * PSECURITY_DESCRIPTOR pAbsoluteSecurityDescriptor
    * LPDWORD lpdwAbsoluteSecurityDescriptorSize
    * PACL pDacl
    * LPDWORD lpdwDaclSize
    * PACL pSacl
    * LPDWORD lpdwSaclSize
    * PSID pOwner
    * LPDWORD lpdwOwnerSize
    * PSID pPrimaryGroup
    * LPDWORD lpdwPrimaryGroupSize


MakeSelfRelativeSD
==================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pAbsoluteSecurityDescriptor
    * PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor
    * LPDWORD lpdwBufferLength


MapGenericMask
==============

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PDWORD AccessMask
    * PGENERIC_MAPPING GenericMapping


ObjectCloseAuditAlarmA
======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR SubsystemName
    * LPVOID HandleId
    * BOOL GenerateOnClose


ObjectCloseAuditAlarmW
======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR SubsystemName
    * LPVOID HandleId
    * BOOL GenerateOnClose


ObjectDeleteAuditAlarmA
=======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR SubsystemName
    * LPVOID HandleId
    * BOOL GenerateOnClose


ObjectDeleteAuditAlarmW
=======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR SubsystemName
    * LPVOID HandleId
    * BOOL GenerateOnClose


ObjectOpenAuditAlarmA
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR SubsystemName
    * LPVOID HandleId
    * LPSTR ObjectTypeName
    * LPSTR ObjectName
    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * HANDLE ClientToken
    * DWORD DesiredAccess
    * DWORD GrantedAccess
    * PPRIVILEGE_SET Privileges
    * BOOL ObjectCreation
    * BOOL AccessGranted
    * LPBOOL GenerateOnClose


ObjectOpenAuditAlarmW
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR SubsystemName
    * LPVOID HandleId
    * LPWSTR ObjectTypeName
    * LPWSTR ObjectName
    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * HANDLE ClientToken
    * DWORD DesiredAccess
    * DWORD GrantedAccess
    * PPRIVILEGE_SET Privileges
    * BOOL ObjectCreation
    * BOOL AccessGranted
    * LPBOOL GenerateOnClose


ObjectPrivilegeAuditAlarmA
==========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR SubsystemName
    * LPVOID HandleId
    * HANDLE ClientToken
    * DWORD DesiredAccess
    * PPRIVILEGE_SET Privileges
    * BOOL AccessGranted


ObjectPrivilegeAuditAlarmW
==========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR SubsystemName
    * LPVOID HandleId
    * HANDLE ClientToken
    * DWORD DesiredAccess
    * PPRIVILEGE_SET Privileges
    * BOOL AccessGranted


OpenProcessToken
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE ProcessHandle
    * DWORD DesiredAccess
    * PHANDLE TokenHandle


OpenThreadToken
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE ThreadHandle
    * DWORD DesiredAccess
    * BOOL OpenAsSelf
    * PHANDLE TokenHandle


PrivilegeCheck
==============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE ClientToken
    * PPRIVILEGE_SET RequiredPrivileges
    * LPBOOL pfResult


PrivilegedServiceAuditAlarmA
============================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR SubsystemName
    * LPCSTR ServiceName
    * HANDLE ClientToken
    * PPRIVILEGE_SET Privileges
    * BOOL AccessGranted


PrivilegedServiceAuditAlarmW
============================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR SubsystemName
    * LPCWSTR ServiceName
    * HANDLE ClientToken
    * PPRIVILEGE_SET Privileges
    * BOOL AccessGranted


QuerySecurityAccessMask
=======================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * SECURITY_INFORMATION SecurityInformation
    * LPDWORD DesiredAccess


QueryServiceObjectSecurity
==========================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    * SC_HANDLE hService
    * SECURITY_INFORMATION dwSecurityInformation
    * PSECURITY_DESCRIPTOR lpSecurityDescriptor
    * DWORD cbBufSize
    * LPDWORD pcbBytesNeeded


RegGetKeySecurity
=================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * SECURITY_INFORMATION SecurityInformation
    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * LPDWORD lpcbSecurityDescriptor


RegSetKeySecurity
=================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * SECURITY_INFORMATION SecurityInformation
    * PSECURITY_DESCRIPTOR pSecurityDescriptor


RevertToSelf
============

Signature::

    * Library: advapi32
    * Return value: BOOL


SetAclInformation
=================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PACL pAcl
    * LPVOID pAclInformation
    * DWORD nAclInformationLength
    * ACL_INFORMATION_CLASS dwAclInformationClass


SetEntriesInAclA
================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * ULONG cCountOfExplicitEntries
    * PEXPLICIT_ACCESS_A pListOfExplicitEntries
    * PACL OldAcl
    * PACL *NewAcl


SetEntriesInAclW
================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * ULONG cCountOfExplicitEntries
    * PEXPLICIT_ACCESS_W pListOfExplicitEntries
    * PACL OldAcl
    * PACL *NewAcl


SetFileSecurityA
================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR lpFileName
    * SECURITY_INFORMATION SecurityInformation
    * PSECURITY_DESCRIPTOR pSecurityDescriptor


SetFileSecurityW
================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName
    * SECURITY_INFORMATION SecurityInformation
    * PSECURITY_DESCRIPTOR pSecurityDescriptor


SetKernelObjectSecurity
=======================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE Handle
    * SECURITY_INFORMATION SecurityInformation
    * PSECURITY_DESCRIPTOR SecurityDescriptor


SetNamedSecurityInfoA
=====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPSTR pObjectName
    * SE_OBJECT_TYPE ObjectType
    * SECURITY_INFORMATION SecurityInfo
    * PSID psidOwner
    * PSID psidGroup
    * PACL pDacl
    * PACL pSacl


SetNamedSecurityInfoW
=====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPWSTR pObjectName
    * SE_OBJECT_TYPE ObjectType
    * SECURITY_INFORMATION SecurityInfo
    * PSID psidOwner
    * PSID psidGroup
    * PACL pDacl
    * PACL pSacl


SetPrivateObjectSecurity
========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * SECURITY_INFORMATION SecurityInformation
    * PSECURITY_DESCRIPTOR ModificationDescriptor
    * PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor
    * PGENERIC_MAPPING GenericMapping
    * HANDLE Token


SetPrivateObjectSecurityEx
==========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * SECURITY_INFORMATION SecurityInformation
    * PSECURITY_DESCRIPTOR ModificationDescriptor
    * PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor
    * ULONG AutoInheritFlags
    * PGENERIC_MAPPING GenericMapping
    * HANDLE Token


SetSecurityAccessMask
=====================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * SECURITY_INFORMATION SecurityInformation
    * LPDWORD DesiredAccess


SetSecurityDescriptorControl
============================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * SECURITY_DESCRIPTOR_CONTROL ControlBitsOfInterest
    * SECURITY_DESCRIPTOR_CONTROL ControlBitsToSet


SetSecurityDescriptorDacl
=========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * BOOL bDaclPresent
    * PACL pDacl
    * BOOL bDaclDefaulted


SetSecurityDescriptorGroup
==========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * PSID pGroup
    * BOOL bGroupDefaulted


SetSecurityDescriptorOwner
==========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * PSID pOwner
    * BOOL bOwnerDefaulted


SetSecurityDescriptorRMControl
==============================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PSECURITY_DESCRIPTOR SecurityDescriptor
    * PUCHAR RMControl


SetSecurityDescriptorSacl
=========================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * PSECURITY_DESCRIPTOR pSecurityDescriptor
    * BOOL bSaclPresent
    * PACL pSacl
    * BOOL bSaclDefaulted


SetSecurityInfo
===============

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * HANDLE handle
    * SE_OBJECT_TYPE ObjectType
    * SECURITY_INFORMATION SecurityInfo
    * PSID psidOwner
    * PSID psidGroup
    * PACL pDacl
    * PACL pSacl


SetServiceObjectSecurity
========================

Signature::

    * Library: sechost
    * Return value: BOOL

Parameters::

    * SC_HANDLE hService
    * SECURITY_INFORMATION dwSecurityInformation
    * PSECURITY_DESCRIPTOR lpSecurityDescriptor


SetThreadToken
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * PHANDLE Thread
    * HANDLE Token


SetTokenInformation
===================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * HANDLE TokenHandle
    * TOKEN_INFORMATION_CLASS TokenInformationClass
    * LPVOID TokenInformation
    * DWORD TokenInformationLength


SetUserObjectSecurity
=====================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    * HANDLE hObj
    * PSECURITY_INFORMATION pSIRequested
    * PSECURITY_DESCRIPTOR pSID


TreeResetNamedSecurityInfoA
===========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPSTR pObjectName
    * SE_OBJECT_TYPE ObjectType
    * SECURITY_INFORMATION SecurityInfo
    * PSID pOwner
    * PSID pGroup
    * PACL pDacl
    * PACL pSacl
    * BOOL KeepExplicit
    * FN_PROGRESS fnProgress
    * PROG_INVOKE_SETTING ProgressInvokeSetting
    * PVOID Args


TreeResetNamedSecurityInfoW
===========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPWSTR pObjectName
    * SE_OBJECT_TYPE ObjectType
    * SECURITY_INFORMATION SecurityInfo
    * PSID pOwner
    * PSID pGroup
    * PACL pDacl
    * PACL pSacl
    * BOOL KeepExplicit
    * FN_PROGRESS fnProgress
    * PROG_INVOKE_SETTING ProgressInvokeSetting
    * PVOID Args


TreeSetNamedSecurityInfoA
=========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPSTR pObjectName
    * SE_OBJECT_TYPE ObjectType
    * SECURITY_INFORMATION SecurityInfo
    * PSID pOwner
    * PSID pGroup
    * PACL pDacl
    * PACL pSacl
    * DWORD dwAction
    * FN_PROGRESS fnProgress
    * PROG_INVOKE_SETTING ProgressInvokeSetting
    * PVOID Args


TreeSetNamedSecurityInfoW
=========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPWSTR pObjectName
    * SE_OBJECT_TYPE ObjectType
    * SECURITY_INFORMATION SecurityInfo
    * PSID pOwner
    * PSID pGroup
    * PACL pDacl
    * PACL pSacl
    * DWORD dwAction
    * FN_PROGRESS fnProgress
    * PROG_INVOKE_SETTING ProgressInvokeSetting
    * PVOID Args


CertAddCRLContextToStore
========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * PCCRL_CONTEXT pCrlContext
    * DWORD dwAddDisposition
    * PCCRL_CONTEXT *ppStoreContext


CertAddCRLLinkToStore
=====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * PCCRL_CONTEXT pCrlContext
    * DWORD dwAddDisposition
    * PCCRL_CONTEXT *ppStoreContext


CertAddCTLContextToStore
========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * PCCTL_CONTEXT pCtlContext
    * DWORD dwAddDisposition
    * PCCTL_CONTEXT *ppStoreContext


CertAddCTLLinkToStore
=====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * PCCTL_CONTEXT pCtlContext
    * DWORD dwAddDisposition
    * PCCTL_CONTEXT *ppStoreContext


CertAddCertificateContextToStore
================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * PCCERT_CONTEXT pCertContext
    * DWORD dwAddDisposition
    * PCCERT_CONTEXT *ppStoreContext


CertAddCertificateLinkToStore
=============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * PCCERT_CONTEXT pCertContext
    * DWORD dwAddDisposition
    * PCCERT_CONTEXT *ppStoreContext


CertAddEncodedCRLToStore
========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * DWORD dwCertEncodingType
    * const BYTE *pbCrlEncoded
    * DWORD cbCrlEncoded
    * DWORD dwAddDisposition
    * PCCRL_CONTEXT *ppCrlContext


CertAddEncodedCTLToStore
========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * DWORD dwMsgAndCertEncodingType
    * const BYTE *pbCtlEncoded
    * DWORD cbCtlEncoded
    * DWORD dwAddDisposition
    * PCCTL_CONTEXT *ppCtlContext


CertAddEncodedCertificateToStore
================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * DWORD dwCertEncodingType
    * const BYTE *pbCertEncoded
    * DWORD cbCertEncoded
    * DWORD dwAddDisposition
    * PCCERT_CONTEXT *ppCertContext


CertAddEnhancedKeyUsageIdentifier
=================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCertContext
    * LPCSTR pszUsageIdentifier


CertAddRefServerOcspResponse
============================

Signature::

    * Library: crypt32
    * Return value: void

Parameters::

    * HCERT_SERVER_OCSP_RESPONSE hServerOcspResponse


CertAddRefServerOcspResponseContext
===================================

Signature::

    * Library: crypt32
    * Return value: void

Parameters::

    * PCCERT_SERVER_OCSP_RESPONSE_CONTEXT pServerOcspResponseContext


CertAddSerializedElementToStore
===============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * const BYTE *pbElement
    * DWORD cbElement
    * DWORD dwAddDisposition
    * DWORD dwFlags
    * DWORD dwContextTypeFlags
    * DWORD *pdwContextType
    * const void **ppvContext


CertAddStoreToCollection
========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCollectionStore
    * HCERTSTORE hSiblingStore
    * DWORD dwUpdateFlags
    * DWORD dwPriority


CertAlgIdToOID
==============

Signature::

    * Library: crypt32
    * Return value: LPCSTR

Parameters::

    * DWORD dwAlgId


CertCloseServerOcspResponse
===========================

Signature::

    * Library: crypt32
    * Return value: void

Parameters::

    * HCERT_SERVER_OCSP_RESPONSE hServerOcspResponse
    * DWORD dwFlags


CertCloseStore
==============

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * DWORD dwFlags


CertCompareCertificate
======================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * PCERT_INFO pCertId1
    * PCERT_INFO pCertId2


CertCompareCertificateName
==========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * PCERT_NAME_BLOB pCertName1
    * PCERT_NAME_BLOB pCertName2


CertCompareIntegerBlob
======================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_INTEGER_BLOB pInt1
    * PCRYPT_INTEGER_BLOB pInt2


CertComparePublicKeyInfo
========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * PCERT_PUBLIC_KEY_INFO pPublicKey1
    * PCERT_PUBLIC_KEY_INFO pPublicKey2


CertControlStore
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * DWORD dwFlags
    * DWORD dwCtrlType
    * void *pvCtrlPara


CertCreateCRLContext
====================

Signature::

    * Library: crypt32
    * Return value: PCCRL_CONTEXT

Parameters::

    * DWORD dwCertEncodingType
    * const BYTE *pbCrlEncoded
    * DWORD cbCrlEncoded


CertCreateCTLContext
====================

Signature::

    * Library: crypt32
    * Return value: PCCTL_CONTEXT

Parameters::

    * DWORD dwMsgAndCertEncodingType
    * const BYTE *pbCtlEncoded
    * DWORD cbCtlEncoded


CertCreateCTLEntryFromCertificateContextProperties
==================================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCertContext
    * DWORD cOptAttr
    * PCRYPT_ATTRIBUTE rgOptAttr
    * DWORD dwFlags
    * void *pvReserved
    * PCTL_ENTRY pCtlEntry
    * DWORD *pcbCtlEntry


CertCreateCertificateChainEngine
================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCERT_CHAIN_ENGINE_CONFIG pConfig
    * HCERTCHAINENGINE *phChainEngine


CertCreateCertificateContext
============================

Signature::

    * Library: crypt32
    * Return value: PCCERT_CONTEXT

Parameters::

    * DWORD dwCertEncodingType
    * const BYTE *pbCertEncoded
    * DWORD cbCertEncoded


CertCreateContext
=================

Signature::

    * Library: crypt32
    * Return value: const void *

Parameters::

    * DWORD dwContextType
    * DWORD dwEncodingType
    * const BYTE *pbEncoded
    * DWORD cbEncoded
    * DWORD dwFlags
    * PCERT_CREATE_CONTEXT_PARA pCreatePara


CertCreateSelfSignCertificate
=============================

Signature::

    * Library: crypt32
    * Return value: PCCERT_CONTEXT

Parameters::

    * HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey
    * PCERT_NAME_BLOB pSubjectIssuerBlob
    * DWORD dwFlags
    * PCRYPT_KEY_PROV_INFO pKeyProvInfo
    * PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm
    * PSYSTEMTIME pStartTime
    * PSYSTEMTIME pEndTime
    * PCERT_EXTENSIONS pExtensions


CertDeleteCRLFromStore
======================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCRL_CONTEXT pCrlContext


CertDeleteCTLFromStore
======================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCTL_CONTEXT pCtlContext


CertDeleteCertificateFromStore
==============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCertContext


CertDuplicateCRLContext
=======================

Signature::

    * Library: crypt32
    * Return value: PCCRL_CONTEXT

Parameters::

    * PCCRL_CONTEXT pCrlContext


CertDuplicateCTLContext
=======================

Signature::

    * Library: crypt32
    * Return value: PCCTL_CONTEXT

Parameters::

    * PCCTL_CONTEXT pCtlContext


CertDuplicateCertificateChain
=============================

Signature::

    * Library: crypt32
    * Return value: PCCERT_CHAIN_CONTEXT

Parameters::

    * PCCERT_CHAIN_CONTEXT pChainContext


CertDuplicateCertificateContext
===============================

Signature::

    * Library: crypt32
    * Return value: PCCERT_CONTEXT

Parameters::

    * PCCERT_CONTEXT pCertContext


CertDuplicateStore
==================

Signature::

    * Library: crypt32
    * Return value: HCERTSTORE

Parameters::

    * HCERTSTORE hCertStore


CertEnumCRLContextProperties
============================

Signature::

    * Library: crypt32
    * Return value: DWORD

Parameters::

    * PCCRL_CONTEXT pCrlContext
    * DWORD dwPropId


CertEnumCRLsInStore
===================

Signature::

    * Library: crypt32
    * Return value: PCCRL_CONTEXT

Parameters::

    * HCERTSTORE hCertStore
    * PCCRL_CONTEXT pPrevCrlContext


CertEnumCTLContextProperties
============================

Signature::

    * Library: crypt32
    * Return value: DWORD

Parameters::

    * PCCTL_CONTEXT pCtlContext
    * DWORD dwPropId


CertEnumCTLsInStore
===================

Signature::

    * Library: crypt32
    * Return value: PCCTL_CONTEXT

Parameters::

    * HCERTSTORE hCertStore
    * PCCTL_CONTEXT pPrevCtlContext


CertEnumCertificateContextProperties
====================================

Signature::

    * Library: crypt32
    * Return value: DWORD

Parameters::

    * PCCERT_CONTEXT pCertContext
    * DWORD dwPropId


CertEnumCertificatesInStore
===========================

Signature::

    * Library: crypt32
    * Return value: PCCERT_CONTEXT

Parameters::

    * HCERTSTORE hCertStore
    * PCCERT_CONTEXT pPrevCertContext


CertEnumPhysicalStore
=====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * const void *pvSystemStore
    * DWORD dwFlags
    * void *pvArg


CertEnumSubjectInSortedCTL
==========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCTL_CONTEXT pCtlContext
    * void **ppvNextSubject
    * PCRYPT_DER_BLOB pSubjectIdentifier
    * PCRYPT_DER_BLOB pEncodedAttributes


CertEnumSystemStore
===================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwFlags
    * void *pvSystemStoreLocationPara
    * void *pvArg


CertEnumSystemStoreLocation
===========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwFlags
    * void *pvArg


CertFindAttribute
=================

Signature::

    * Library: crypt32
    * Return value: PCRYPT_ATTRIBUTE

Parameters::

    * LPCSTR pszObjId
    * DWORD cAttr
    * CRYPT_ATTRIBUTE rgAttr[]


CertFindCRLInStore
==================

Signature::

    * Library: crypt32
    * Return value: PCCRL_CONTEXT

Parameters::

    * HCERTSTORE hCertStore
    * DWORD dwCertEncodingType
    * DWORD dwFindFlags
    * DWORD dwFindType
    * const void *pvFindPara
    * PCCRL_CONTEXT pPrevCrlContext


CertFindCTLInStore
==================

Signature::

    * Library: crypt32
    * Return value: PCCTL_CONTEXT

Parameters::

    * HCERTSTORE hCertStore
    * DWORD dwMsgAndCertEncodingType
    * DWORD dwFindFlags
    * DWORD dwFindType
    * const void *pvFindPara
    * PCCTL_CONTEXT pPrevCtlContext


CertFindCertificateInCRL
========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCert
    * PCCRL_CONTEXT pCrlContext
    * DWORD dwFlags
    * void *pvReserved
    * PCRL_ENTRY *ppCrlEntry


CertFindCertificateInStore
==========================

Signature::

    * Library: crypt32
    * Return value: PCCERT_CONTEXT

Parameters::

    * HCERTSTORE hCertStore
    * DWORD dwCertEncodingType
    * DWORD dwFindFlags
    * DWORD dwFindType
    * const void *pvFindPara
    * PCCERT_CONTEXT pPrevCertContext


CertFindChainInStore
====================

Signature::

    * Library: crypt32
    * Return value: PCCERT_CHAIN_CONTEXT

Parameters::

    * HCERTSTORE hCertStore
    * DWORD dwCertEncodingType
    * DWORD dwFindFlags
    * DWORD dwFindType
    * const void *pvFindPara
    * PCCERT_CHAIN_CONTEXT pPrevChainContext


CertFindExtension
=================

Signature::

    * Library: crypt32
    * Return value: PCERT_EXTENSION

Parameters::

    * LPCSTR pszObjId
    * DWORD cExtensions
    * CERT_EXTENSION rgExtensions[]


CertFindRDNAttr
===============

Signature::

    * Library: crypt32
    * Return value: PCERT_RDN_ATTR

Parameters::

    * LPCSTR pszObjId
    * PCERT_NAME_INFO pName


CertFindSubjectInCTL
====================

Signature::

    * Library: crypt32
    * Return value: PCTL_ENTRY

Parameters::

    * DWORD dwEncodingType
    * DWORD dwSubjectType
    * void *pvSubject
    * PCCTL_CONTEXT pCtlContext
    * DWORD dwFlags


CertFindSubjectInSortedCTL
==========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_DATA_BLOB pSubjectIdentifier
    * PCCTL_CONTEXT pCtlContext
    * DWORD dwFlags
    * void *pvReserved
    * PCRYPT_DER_BLOB pEncodedAttributes


CertFreeCRLContext
==================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCRL_CONTEXT pCrlContext


CertFreeCTLContext
==================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCTL_CONTEXT pCtlContext


CertFreeCertificateChain
========================

Signature::

    * Library: crypt32
    * Return value: void

Parameters::

    * PCCERT_CHAIN_CONTEXT pChainContext


CertFreeCertificateChainEngine
==============================

Signature::

    * Library: crypt32
    * Return value: void

Parameters::

    * HCERTCHAINENGINE hChainEngine


CertFreeCertificateChainList
============================

Signature::

    * Library: crypt32
    * Return value: void

Parameters::

    * PCCERT_CHAIN_CONTEXT *prgpSelection


CertFreeCertificateContext
==========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCertContext


CertGetCRLContextProperty
=========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCRL_CONTEXT pCrlContext
    * DWORD dwPropId
    * void *pvData
    * DWORD *pcbData


CertGetCRLFromStore
===================

Signature::

    * Library: crypt32
    * Return value: PCCRL_CONTEXT

Parameters::

    * HCERTSTORE hCertStore
    * PCCERT_CONTEXT pIssuerContext
    * PCCRL_CONTEXT pPrevCrlContext
    * DWORD *pdwFlags


CertGetCTLContextProperty
=========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCTL_CONTEXT pCtlContext
    * DWORD dwPropId
    * void *pvData
    * DWORD *pcbData


CertGetCertificateChain
=======================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTCHAINENGINE hChainEngine
    * PCCERT_CONTEXT pCertContext
    * LPFILETIME pTime
    * HCERTSTORE hAdditionalStore
    * PCERT_CHAIN_PARA pChainPara
    * DWORD dwFlags
    * LPVOID pvReserved
    * PCCERT_CHAIN_CONTEXT *ppChainContext


CertGetCertificateContextProperty
=================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCertContext
    * DWORD dwPropId
    * void *pvData
    * DWORD *pcbData


CertGetEnhancedKeyUsage
=======================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCertContext
    * DWORD dwFlags
    * PCERT_ENHKEY_USAGE pUsage
    * DWORD *pcbUsage


CertGetIntendedKeyUsage
=======================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * PCERT_INFO pCertInfo
    * BYTE *pbKeyUsage
    * DWORD cbKeyUsage


CertGetIssuerCertificateFromStore
=================================

Signature::

    * Library: crypt32
    * Return value: PCCERT_CONTEXT

Parameters::

    * HCERTSTORE hCertStore
    * PCCERT_CONTEXT pSubjectContext
    * PCCERT_CONTEXT pPrevIssuerContext
    * DWORD *pdwFlags


CertGetNameStringA
==================

Signature::

    * Library: crypt32
    * Return value: DWORD

Parameters::

    * PCCERT_CONTEXT pCertContext
    * DWORD dwType
    * DWORD dwFlags
    * void *pvTypePara
    * LPSTR pszNameString
    * DWORD cchNameString


CertGetNameStringW
==================

Signature::

    * Library: crypt32
    * Return value: DWORD

Parameters::

    * PCCERT_CONTEXT pCertContext
    * DWORD dwType
    * DWORD dwFlags
    * void *pvTypePara
    * LPWSTR pszNameString
    * DWORD cchNameString


CertGetPublicKeyLength
======================

Signature::

    * Library: crypt32
    * Return value: DWORD

Parameters::

    * DWORD dwCertEncodingType
    * PCERT_PUBLIC_KEY_INFO pPublicKey


CertGetServerOcspResponseContext
================================

Signature::

    * Library: crypt32
    * Return value: PCCERT_SERVER_OCSP_RESPONSE_CONTEXT

Parameters::

    * HCERT_SERVER_OCSP_RESPONSE hServerOcspResponse
    * DWORD dwFlags
    * LPVOID pvReserved


CertGetStoreProperty
====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * DWORD dwPropId
    * void *pvData
    * DWORD *pcbData


CertGetSubjectCertificateFromStore
==================================

Signature::

    * Library: crypt32
    * Return value: PCCERT_CONTEXT

Parameters::

    * HCERTSTORE hCertStore
    * DWORD dwCertEncodingType
    * PCERT_INFO pCertId


CertGetValidUsages
==================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD cCerts
    * PCCERT_CONTEXT *rghCerts
    * int *cNumOIDs
    * LPSTR *rghOIDs
    * DWORD *pcbOIDs


CertIsRDNAttrsInCertificateName
===============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * DWORD dwFlags
    * PCERT_NAME_BLOB pCertName
    * PCERT_RDN pRDN


CertIsValidCRLForCertificate
============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCert
    * PCCRL_CONTEXT pCrl
    * DWORD dwFlags
    * void *pvReserved


CertNameToStrA
==============

Signature::

    * Library: crypt32
    * Return value: DWORD

Parameters::

    * DWORD dwCertEncodingType
    * PCERT_NAME_BLOB pName
    * DWORD dwStrType
    * LPSTR psz
    * DWORD csz


CertNameToStrW
==============

Signature::

    * Library: crypt32
    * Return value: DWORD

Parameters::

    * DWORD dwCertEncodingType
    * PCERT_NAME_BLOB pName
    * DWORD dwStrType
    * LPWSTR psz
    * DWORD csz


CertOIDToAlgId
==============

Signature::

    * Library: crypt32
    * Return value: DWORD

Parameters::

    * LPCSTR pszObjId


CertOpenServerOcspResponse
==========================

Signature::

    * Library: crypt32
    * Return value: HCERT_SERVER_OCSP_RESPONSE

Parameters::

    * PCCERT_CHAIN_CONTEXT pChainContext
    * DWORD dwFlags
    * LPVOID pvReserved


CertOpenStore
=============

Signature::

    * Library: crypt32
    * Return value: HCERTSTORE

Parameters::

    * LPCSTR lpszStoreProvider
    * DWORD dwEncodingType
    * HCRYPTPROV_LEGACY hCryptProv
    * DWORD dwFlags
    * const void *pvPara


CertOpenSystemStoreA
====================

Signature::

    * Library: crypt32
    * Return value: HCERTSTORE

Parameters::

    * HCRYPTPROV_LEGACY hProv
    * LPCSTR szSubsystemProtocol


CertOpenSystemStoreW
====================

Signature::

    * Library: crypt32
    * Return value: HCERTSTORE

Parameters::

    * HCRYPTPROV_LEGACY hProv
    * LPCWSTR szSubsystemProtocol


CertRDNValueToStrA
==================

Signature::

    * Library: crypt32
    * Return value: DWORD

Parameters::

    * DWORD dwValueType
    * PCERT_RDN_VALUE_BLOB pValue
    * LPSTR psz
    * DWORD csz


CertRDNValueToStrW
==================

Signature::

    * Library: crypt32
    * Return value: DWORD

Parameters::

    * DWORD dwValueType
    * PCERT_RDN_VALUE_BLOB pValue
    * LPWSTR psz
    * DWORD csz


CertRegisterPhysicalStore
=========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * const void *pvSystemStore
    * DWORD dwFlags
    * LPCWSTR pwszStoreName
    * PCERT_PHYSICAL_STORE_INFO pStoreInfo
    * void *pvReserved


CertRegisterSystemStore
=======================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * const void *pvSystemStore
    * DWORD dwFlags
    * PCERT_SYSTEM_STORE_INFO pStoreInfo
    * void *pvReserved


CertRemoveEnhancedKeyUsageIdentifier
====================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCertContext
    * LPCSTR pszUsageIdentifier


CertRemoveStoreFromCollection
=============================

Signature::

    * Library: crypt32
    * Return value: void

Parameters::

    * HCERTSTORE hCollectionStore
    * HCERTSTORE hSiblingStore


CertRetrieveLogoOrBiometricInfo
===============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCertContext
    * LPCSTR lpszLogoOrBiometricType
    * DWORD dwRetrievalFlags
    * DWORD dwTimeout
    * DWORD dwFlags
    * void *pvReserved
    * DWORD *pcbData
    * LPWSTR *ppwszMimeType


CertSaveStore
=============

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * DWORD dwEncodingType
    * DWORD dwSaveAs
    * DWORD dwSaveTo
    * void *pvSaveToPara
    * DWORD dwFlags


CertSelectCertificateChains
===========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * LPCGUID pSelectionContext
    * DWORD dwFlags
    * PCCERT_SELECT_CHAIN_PARA pChainParameters
    * DWORD cCriteria
    * PCCERT_SELECT_CRITERIA rgpCriteria
    * HCERTSTORE hStore
    * PDWORD pcSelection
    * PCCERT_CHAIN_CONTEXT **pprgpSelection


CertSerializeCRLStoreElement
============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCRL_CONTEXT pCrlContext
    * DWORD dwFlags
    * BYTE *pbElement
    * DWORD *pcbElement


CertSerializeCTLStoreElement
============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCTL_CONTEXT pCtlContext
    * DWORD dwFlags
    * BYTE *pbElement
    * DWORD *pcbElement


CertSerializeCertificateStoreElement
====================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCertContext
    * DWORD dwFlags
    * BYTE *pbElement
    * DWORD *pcbElement


CertSetCRLContextProperty
=========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCRL_CONTEXT pCrlContext
    * DWORD dwPropId
    * DWORD dwFlags
    * const void *pvData


CertSetCTLContextProperty
=========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCTL_CONTEXT pCtlContext
    * DWORD dwPropId
    * DWORD dwFlags
    * const void *pvData


CertSetCertificateContextPropertiesFromCTLEntry
===============================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCertContext
    * PCTL_ENTRY pCtlEntry
    * DWORD dwFlags


CertSetCertificateContextProperty
=================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCertContext
    * DWORD dwPropId
    * DWORD dwFlags
    * const void *pvData


CertSetEnhancedKeyUsage
=======================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCertContext
    * PCERT_ENHKEY_USAGE pUsage


CertSetStoreProperty
====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hCertStore
    * DWORD dwPropId
    * DWORD dwFlags
    * const void *pvData


CertStrToNameA
==============

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * LPCSTR pszX500
    * DWORD dwStrType
    * void *pvReserved
    * BYTE *pbEncoded
    * DWORD *pcbEncoded
    * LPCSTR *ppszError


CertStrToNameW
==============

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * LPCWSTR pszX500
    * DWORD dwStrType
    * void *pvReserved
    * BYTE *pbEncoded
    * DWORD *pcbEncoded
    * LPCWSTR *ppszError


CertUnregisterPhysicalStore
===========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * const void *pvSystemStore
    * DWORD dwFlags
    * LPCWSTR pwszStoreName


CertUnregisterSystemStore
=========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * const void *pvSystemStore
    * DWORD dwFlags


CertVerifyCRLRevocation
=======================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * PCERT_INFO pCertId
    * DWORD cCrlInfo
    * PCRL_INFO rgpCrlInfo[]


CertVerifyCRLTimeValidity
=========================

Signature::

    * Library: crypt32
    * Return value: LONG

Parameters::

    * LPFILETIME pTimeToVerify
    * PCRL_INFO pCrlInfo


CertVerifyCTLUsage
==================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwEncodingType
    * DWORD dwSubjectType
    * void *pvSubject
    * PCTL_USAGE pSubjectUsage
    * DWORD dwFlags
    * PCTL_VERIFY_USAGE_PARA pVerifyUsagePara
    * PCTL_VERIFY_USAGE_STATUS pVerifyUsageStatus


CertVerifyCertificateChainPolicy
================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * LPCSTR pszPolicyOID
    * PCCERT_CHAIN_CONTEXT pChainContext
    * PCERT_CHAIN_POLICY_PARA pPolicyPara
    * PCERT_CHAIN_POLICY_STATUS pPolicyStatus


CertVerifyRevocation
====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwEncodingType
    * DWORD dwRevType
    * DWORD cContext
    * PVOID rgpvContext[]
    * DWORD dwFlags
    * PCERT_REVOCATION_PARA pRevPara
    * PCERT_REVOCATION_STATUS pRevStatus


CertVerifySubjectCertificateContext
===================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pSubject
    * PCCERT_CONTEXT pIssuer
    * DWORD *pdwFlags


CertVerifyTimeValidity
======================

Signature::

    * Library: crypt32
    * Return value: LONG

Parameters::

    * LPFILETIME pTimeToVerify
    * PCERT_INFO pCertInfo


CertVerifyValidityNesting
=========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCERT_INFO pSubjectInfo
    * PCERT_INFO pIssuerInfo


CryptAcquireContextA
====================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTPROV *phProv
    * LPCSTR szContainer
    * LPCSTR szProvider
    * DWORD dwProvType
    * DWORD dwFlags


CryptAcquireContextW
====================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTPROV *phProv
    * LPCWSTR szContainer
    * LPCWSTR szProvider
    * DWORD dwProvType
    * DWORD dwFlags


CryptBinaryToStringA
====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * const BYTE *pbBinary
    * DWORD cbBinary
    * DWORD dwFlags
    * LPSTR pszString
    * DWORD *pcchString


CryptBinaryToStringW
====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * const BYTE *pbBinary
    * DWORD cbBinary
    * DWORD dwFlags
    * LPWSTR pszString
    * DWORD *pcchString


CryptContextAddRef
==================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTPROV hProv
    * DWORD *pdwReserved
    * DWORD dwFlags


CryptCreateHash
===============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTPROV hProv
    * ALG_ID Algid
    * HCRYPTKEY hKey
    * DWORD dwFlags
    * HCRYPTHASH *phHash


CryptCreateKeyIdentifierFromCSP
===============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * LPCSTR pszPubKeyOID
    * const PUBLICKEYSTRUC *pPubKeyStruc
    * DWORD cbPubKeyStruc
    * DWORD dwFlags
    * void *pvReserved
    * BYTE *pbHash
    * DWORD *pcbHash


CryptDecodeMessage
==================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwMsgTypeFlags
    * PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara
    * PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara
    * DWORD dwSignerIndex
    * const BYTE *pbEncodedBlob
    * DWORD cbEncodedBlob
    * DWORD dwPrevInnerContentType
    * DWORD *pdwMsgType
    * DWORD *pdwInnerContentType
    * BYTE *pbDecoded
    * DWORD *pcbDecoded
    * PCCERT_CONTEXT *ppXchgCert
    * PCCERT_CONTEXT *ppSignerCert


CryptDecodeObject
=================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * LPCSTR lpszStructType
    * const BYTE *pbEncoded
    * DWORD cbEncoded
    * DWORD dwFlags
    * void *pvStructInfo
    * DWORD *pcbStructInfo


CryptDecodeObjectEx
===================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * LPCSTR lpszStructType
    * const BYTE *pbEncoded
    * DWORD cbEncoded
    * DWORD dwFlags
    * PCRYPT_DECODE_PARA pDecodePara
    * void *pvStructInfo
    * DWORD *pcbStructInfo


CryptDecrypt
============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTKEY hKey
    * HCRYPTHASH hHash
    * BOOL Final
    * DWORD dwFlags
    * BYTE *pbData
    * DWORD *pdwDataLen


CryptDecryptAndVerifyMessageSignature
=====================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara
    * PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara
    * DWORD dwSignerIndex
    * const BYTE *pbEncryptedBlob
    * DWORD cbEncryptedBlob
    * BYTE *pbDecrypted
    * DWORD *pcbDecrypted
    * PCCERT_CONTEXT *ppXchgCert
    * PCCERT_CONTEXT *ppSignerCert


CryptDecryptMessage
===================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara
    * const BYTE *pbEncryptedBlob
    * DWORD cbEncryptedBlob
    * BYTE *pbDecrypted
    * DWORD *pcbDecrypted
    * PCCERT_CONTEXT *ppXchgCert


CryptDeriveKey
==============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTPROV hProv
    * ALG_ID Algid
    * HCRYPTHASH hBaseData
    * DWORD dwFlags
    * HCRYPTKEY *phKey


CryptDestroyHash
================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTHASH hHash


CryptDestroyKey
===============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTKEY hKey


CryptDuplicateHash
==================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTHASH hHash
    * DWORD *pdwReserved
    * DWORD dwFlags
    * HCRYPTHASH *phHash


CryptDuplicateKey
=================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTKEY hKey
    * DWORD *pdwReserved
    * DWORD dwFlags
    * HCRYPTKEY *phKey


CryptEncodeObject
=================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * LPCSTR lpszStructType
    * const void *pvStructInfo
    * BYTE *pbEncoded
    * DWORD *pcbEncoded


CryptEncodeObjectEx
===================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * LPCSTR lpszStructType
    * const void *pvStructInfo
    * DWORD dwFlags
    * PCRYPT_ENCODE_PARA pEncodePara
    * void *pvEncoded
    * DWORD *pcbEncoded


CryptEncrypt
============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTKEY hKey
    * HCRYPTHASH hHash
    * BOOL Final
    * DWORD dwFlags
    * BYTE *pbData
    * DWORD *pdwDataLen
    * DWORD dwBufLen


CryptEncryptMessage
===================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara
    * DWORD cRecipientCert
    * PCCERT_CONTEXT rgpRecipientCert[]
    * const BYTE *pbToBeEncrypted
    * DWORD cbToBeEncrypted
    * BYTE *pbEncryptedBlob
    * DWORD *pcbEncryptedBlob


CryptEnumKeyIdentifierProperties
================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * const CRYPT_HASH_BLOB *pKeyIdentifier
    * DWORD dwPropId
    * DWORD dwFlags
    * LPCWSTR pwszComputerName
    * void *pvReserved
    * void *pvArg


CryptEnumOIDFunction
====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwEncodingType
    * LPCSTR pszFuncName
    * LPCSTR pszOID
    * DWORD dwFlags
    * void *pvArg


CryptEnumOIDInfo
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwGroupId
    * DWORD dwFlags
    * void *pvArg


CryptEnumProviderTypesA
=======================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * DWORD dwIndex
    * DWORD *pdwReserved
    * DWORD dwFlags
    * DWORD *pdwProvType
    * LPSTR szTypeName
    * DWORD *pcbTypeName


CryptEnumProviderTypesW
=======================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * DWORD dwIndex
    * DWORD *pdwReserved
    * DWORD dwFlags
    * DWORD *pdwProvType
    * LPWSTR szTypeName
    * DWORD *pcbTypeName


CryptEnumProvidersA
===================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * DWORD dwIndex
    * DWORD *pdwReserved
    * DWORD dwFlags
    * DWORD *pdwProvType
    * LPSTR szProvName
    * DWORD *pcbProvName


CryptEnumProvidersW
===================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * DWORD dwIndex
    * DWORD *pdwReserved
    * DWORD dwFlags
    * DWORD *pdwProvType
    * LPWSTR szProvName
    * DWORD *pcbProvName


CryptExportKey
==============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTKEY hKey
    * HCRYPTKEY hExpKey
    * DWORD dwBlobType
    * DWORD dwFlags
    * BYTE *pbData
    * DWORD *pdwDataLen


CryptExportPKCS8
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV hCryptProv
    * DWORD dwKeySpec
    * LPSTR pszPrivateKeyObjId
    * DWORD dwFlags
    * void *pvAuxInfo
    * BYTE *pbPrivateKeyBlob
    * DWORD *pcbPrivateKeyBlob


CryptExportPublicKeyInfo
========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey
    * DWORD dwKeySpec
    * DWORD dwCertEncodingType
    * PCERT_PUBLIC_KEY_INFO pInfo
    * DWORD *pcbInfo


CryptExportPublicKeyInfoEx
==========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey
    * DWORD dwKeySpec
    * DWORD dwCertEncodingType
    * LPSTR pszPublicKeyObjId
    * DWORD dwFlags
    * void *pvAuxInfo
    * PCERT_PUBLIC_KEY_INFO pInfo
    * DWORD *pcbInfo


CryptExportPublicKeyInfoFromBCryptKeyHandle
===========================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * BCRYPT_KEY_HANDLE hBCryptKey
    * DWORD dwCertEncodingType
    * LPSTR pszPublicKeyObjId
    * DWORD dwFlags
    * void *pvAuxInfo
    * PCERT_PUBLIC_KEY_INFO pInfo
    * DWORD *pcbInfo


CryptFindCertificateKeyProvInfo
===============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCERT_CONTEXT pCert
    * DWORD dwFlags
    * void *pvReserved


CryptFindLocalizedName
======================

Signature::

    * Library: crypt32
    * Return value: LPCWSTR

Parameters::

    * LPCWSTR pwszCryptName


CryptFindOIDInfo
================

Signature::

    * Library: crypt32
    * Return value: PCCRYPT_OID_INFO

Parameters::

    * DWORD dwKeyType
    * void *pvKey
    * DWORD dwGroupId


CryptFormatObject
=================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * DWORD dwFormatType
    * DWORD dwFormatStrType
    * void *pFormatStruct
    * LPCSTR lpszStructType
    * const BYTE *pbEncoded
    * DWORD cbEncoded
    * void *pbFormat
    * DWORD *pcbFormat


CryptFreeOIDFunctionAddress
===========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTOIDFUNCADDR hFuncAddr
    * DWORD dwFlags


CryptGenKey
===========

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTPROV hProv
    * ALG_ID Algid
    * DWORD dwFlags
    * HCRYPTKEY *phKey


CryptGenRandom
==============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTPROV hProv
    * DWORD dwLen
    * BYTE *pbBuffer


CryptGetDefaultOIDDllList
=========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTOIDFUNCSET hFuncSet
    * DWORD dwEncodingType
    * WCHAR *pwszDllList
    * DWORD *pcchDllList


CryptGetDefaultOIDFunctionAddress
=================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTOIDFUNCSET hFuncSet
    * DWORD dwEncodingType
    * LPCWSTR pwszDll
    * DWORD dwFlags
    * void **ppvFuncAddr
    * HCRYPTOIDFUNCADDR *phFuncAddr


CryptGetDefaultProviderA
========================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * DWORD dwProvType
    * DWORD *pdwReserved
    * DWORD dwFlags
    * LPSTR pszProvName
    * DWORD *pcbProvName


CryptGetDefaultProviderW
========================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * DWORD dwProvType
    * DWORD *pdwReserved
    * DWORD dwFlags
    * LPWSTR pszProvName
    * DWORD *pcbProvName


CryptGetHashParam
=================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTHASH hHash
    * DWORD dwParam
    * BYTE *pbData
    * DWORD *pdwDataLen
    * DWORD dwFlags


CryptGetKeyIdentifierProperty
=============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * const CRYPT_HASH_BLOB *pKeyIdentifier
    * DWORD dwPropId
    * DWORD dwFlags
    * LPCWSTR pwszComputerName
    * void *pvReserved
    * void *pvData
    * DWORD *pcbData


CryptGetKeyParam
================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTKEY hKey
    * DWORD dwParam
    * BYTE *pbData
    * DWORD *pdwDataLen
    * DWORD dwFlags


CryptGetMessageCertificates
===========================

Signature::

    * Library: crypt32
    * Return value: HCERTSTORE

Parameters::

    * DWORD dwMsgAndCertEncodingType
    * HCRYPTPROV_LEGACY hCryptProv
    * DWORD dwFlags
    * const BYTE *pbSignedBlob
    * DWORD cbSignedBlob


CryptGetMessageSignerCount
==========================

Signature::

    * Library: crypt32
    * Return value: LONG

Parameters::

    * DWORD dwMsgEncodingType
    * const BYTE *pbSignedBlob
    * DWORD cbSignedBlob


CryptGetOIDFunctionAddress
==========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTOIDFUNCSET hFuncSet
    * DWORD dwEncodingType
    * LPCSTR pszOID
    * DWORD dwFlags
    * void **ppvFuncAddr
    * HCRYPTOIDFUNCADDR *phFuncAddr


CryptGetOIDFunctionValue
========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwEncodingType
    * LPCSTR pszFuncName
    * LPCSTR pszOID
    * LPCWSTR pwszValueName
    * DWORD *pdwValueType
    * BYTE *pbValueData
    * DWORD *pcbValueData


CryptGetObjectUrl
=================

Signature::

    * Library: cryptnet
    * Return value: BOOL

Parameters::

    * LPCSTR pszUrlOid
    * LPVOID pvPara
    * DWORD dwFlags
    * PCRYPT_URL_ARRAY pUrlArray
    * DWORD *pcbUrlArray
    * PCRYPT_URL_INFO pUrlInfo
    * DWORD *pcbUrlInfo
    * LPVOID pvReserved


CryptGetProvParam
=================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTPROV hProv
    * DWORD dwParam
    * BYTE *pbData
    * DWORD *pdwDataLen
    * DWORD dwFlags


CryptGetUserKey
===============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTPROV hProv
    * DWORD dwKeySpec
    * HCRYPTKEY *phUserKey


CryptHashCertificate
====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV_LEGACY hCryptProv
    * ALG_ID Algid
    * DWORD dwFlags
    * const BYTE *pbEncoded
    * DWORD cbEncoded
    * BYTE *pbComputedHash
    * DWORD *pcbComputedHash


CryptHashCertificate2
=====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * LPCWSTR pwszCNGHashAlgid
    * DWORD dwFlags
    * void *pvReserved
    * const BYTE *pbEncoded
    * DWORD cbEncoded
    * BYTE *pbComputedHash
    * DWORD *pcbComputedHash


CryptHashData
=============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTHASH hHash
    * const BYTE *pbData
    * DWORD dwDataLen
    * DWORD dwFlags


CryptHashMessage
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_HASH_MESSAGE_PARA pHashPara
    * BOOL fDetachedHash
    * DWORD cToBeHashed
    * const BYTE *rgpbToBeHashed[]
    * DWORD rgcbToBeHashed[]
    * BYTE *pbHashedBlob
    * DWORD *pcbHashedBlob
    * BYTE *pbComputedHash
    * DWORD *pcbComputedHash


CryptHashPublicKeyInfo
======================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV_LEGACY hCryptProv
    * ALG_ID Algid
    * DWORD dwFlags
    * DWORD dwCertEncodingType
    * PCERT_PUBLIC_KEY_INFO pInfo
    * BYTE *pbComputedHash
    * DWORD *pcbComputedHash


CryptHashSessionKey
===================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTHASH hHash
    * HCRYPTKEY hKey
    * DWORD dwFlags


CryptHashToBeSigned
===================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV_LEGACY hCryptProv
    * DWORD dwCertEncodingType
    * const BYTE *pbEncoded
    * DWORD cbEncoded
    * BYTE *pbComputedHash
    * DWORD *pcbComputedHash


CryptImportKey
==============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTPROV hProv
    * const BYTE *pbData
    * DWORD dwDataLen
    * HCRYPTKEY hPubKey
    * DWORD dwFlags
    * HCRYPTKEY *phKey


CryptImportPKCS8
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * CRYPT_PKCS8_IMPORT_PARAMS sPrivateKeyAndParams
    * DWORD dwFlags
    * HCRYPTPROV *phCryptProv
    * void *pvAuxInfo


CryptImportPublicKeyInfo
========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV hCryptProv
    * DWORD dwCertEncodingType
    * PCERT_PUBLIC_KEY_INFO pInfo
    * HCRYPTKEY *phKey


CryptImportPublicKeyInfoEx
==========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV hCryptProv
    * DWORD dwCertEncodingType
    * PCERT_PUBLIC_KEY_INFO pInfo
    * ALG_ID aiKeyAlg
    * DWORD dwFlags
    * void *pvAuxInfo
    * HCRYPTKEY *phKey


CryptImportPublicKeyInfoEx2
===========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwCertEncodingType
    * PCERT_PUBLIC_KEY_INFO pInfo
    * DWORD dwFlags
    * void *pvAuxInfo
    * BCRYPT_KEY_HANDLE *phKey


CryptInitOIDFunctionSet
=======================

Signature::

    * Library: crypt32
    * Return value: HCRYPTOIDFUNCSET

Parameters::

    * LPCSTR pszFuncName
    * DWORD dwFlags


CryptInstallDefaultContext
==========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV hCryptProv
    * DWORD dwDefaultType
    * const void *pvDefaultPara
    * DWORD dwFlags
    * void *pvReserved
    * HCRYPTDEFAULTCONTEXT *phDefaultContext


CryptInstallOIDFunctionAddress
==============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HMODULE hModule
    * DWORD dwEncodingType
    * LPCSTR pszFuncName
    * DWORD cFuncEntry
    * const CRYPT_OID_FUNC_ENTRY rgFuncEntry[]
    * DWORD dwFlags


CryptMemAlloc
=============

Signature::

    * Library: crypt32
    * Return value: LPVOID

Parameters::

    * ULONG cbSize


CryptMemFree
============

Signature::

    * Library: crypt32
    * Return value: void

Parameters::

    * LPVOID pv


CryptMemRealloc
===============

Signature::

    * Library: crypt32
    * Return value: LPVOID

Parameters::

    * LPVOID pv
    * ULONG cbSize


CryptMsgCalculateEncodedLength
==============================

Signature::

    * Library: crypt32
    * Return value: DWORD

Parameters::

    * DWORD dwMsgEncodingType
    * DWORD dwFlags
    * DWORD dwMsgType
    * void *pvMsgEncodeInfo
    * LPSTR pszInnerContentObjID
    * DWORD cbData


CryptMsgClose
=============

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTMSG hCryptMsg


CryptMsgControl
===============

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTMSG hCryptMsg
    * DWORD dwFlags
    * DWORD dwCtrlType
    * void *pvCtrlPara


CryptMsgCountersign
===================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTMSG hCryptMsg
    * DWORD dwIndex
    * DWORD cCountersigners
    * PCMSG_SIGNER_ENCODE_INFO rgCountersigners


CryptMsgCountersignEncoded
==========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwEncodingType
    * PBYTE pbSignerInfo
    * DWORD cbSignerInfo
    * DWORD cCountersigners
    * PCMSG_SIGNER_ENCODE_INFO rgCountersigners
    * PBYTE pbCountersignature
    * PDWORD pcbCountersignature


CryptMsgDuplicate
=================

Signature::

    * Library: crypt32
    * Return value: HCRYPTMSG

Parameters::

    * HCRYPTMSG hCryptMsg


CryptMsgEncodeAndSignCTL
========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwMsgEncodingType
    * PCTL_INFO pCtlInfo
    * PCMSG_SIGNED_ENCODE_INFO pSignInfo
    * DWORD dwFlags
    * BYTE *pbEncoded
    * DWORD *pcbEncoded


CryptMsgGetAndVerifySigner
==========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTMSG hCryptMsg
    * DWORD cSignerStore
    * HCERTSTORE *rghSignerStore
    * DWORD dwFlags
    * PCCERT_CONTEXT *ppSigner
    * DWORD *pdwSignerIndex


CryptMsgGetParam
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTMSG hCryptMsg
    * DWORD dwParamType
    * DWORD dwIndex
    * void *pvData
    * DWORD *pcbData


CryptMsgOpenToDecode
====================

Signature::

    * Library: crypt32
    * Return value: HCRYPTMSG

Parameters::

    * DWORD dwMsgEncodingType
    * DWORD dwFlags
    * DWORD dwMsgType
    * HCRYPTPROV_LEGACY hCryptProv
    * PCERT_INFO pRecipientInfo
    * PCMSG_STREAM_INFO pStreamInfo


CryptMsgOpenToEncode
====================

Signature::

    * Library: crypt32
    * Return value: HCRYPTMSG

Parameters::

    * DWORD dwMsgEncodingType
    * DWORD dwFlags
    * DWORD dwMsgType
    * void *pvMsgEncodeInfo
    * LPSTR pszInnerContentObjID
    * PCMSG_STREAM_INFO pStreamInfo


CryptMsgSignCTL
===============

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwMsgEncodingType
    * BYTE *pbCtlContent
    * DWORD cbCtlContent
    * PCMSG_SIGNED_ENCODE_INFO pSignInfo
    * DWORD dwFlags
    * BYTE *pbEncoded
    * DWORD *pcbEncoded


CryptMsgUpdate
==============

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTMSG hCryptMsg
    * const BYTE *pbData
    * DWORD cbData
    * BOOL fFinal


CryptMsgVerifyCountersignatureEncoded
=====================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV_LEGACY hCryptProv
    * DWORD dwEncodingType
    * PBYTE pbSignerInfo
    * DWORD cbSignerInfo
    * PBYTE pbSignerInfoCountersignature
    * DWORD cbSignerInfoCountersignature
    * PCERT_INFO pciCountersigner


CryptMsgVerifyCountersignatureEncodedEx
=======================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV_LEGACY hCryptProv
    * DWORD dwEncodingType
    * PBYTE pbSignerInfo
    * DWORD cbSignerInfo
    * PBYTE pbSignerInfoCountersignature
    * DWORD cbSignerInfoCountersignature
    * DWORD dwSignerType
    * void *pvSigner
    * DWORD dwFlags
    * void *pvExtra


CryptProtectData
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DATA_BLOB *pDataIn
    * LPCWSTR szDataDescr
    * DATA_BLOB *pOptionalEntropy
    * PVOID pvReserved
    * CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct
    * DWORD dwFlags
    * DATA_BLOB *pDataOut


CryptProtectMemory
==================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * LPVOID pDataIn
    * DWORD cbDataIn
    * DWORD dwFlags


CryptQueryObject
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwObjectType
    * const void *pvObject
    * DWORD dwExpectedContentTypeFlags
    * DWORD dwExpectedFormatTypeFlags
    * DWORD dwFlags
    * DWORD *pdwMsgAndCertEncodingType
    * DWORD *pdwContentType
    * DWORD *pdwFormatType
    * HCERTSTORE *phCertStore
    * HCRYPTMSG *phMsg
    * const void **ppvContext


CryptRegisterDefaultOIDFunction
===============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwEncodingType
    * LPCSTR pszFuncName
    * DWORD dwIndex
    * LPCWSTR pwszDll


CryptRegisterOIDFunction
========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwEncodingType
    * LPCSTR pszFuncName
    * LPCSTR pszOID
    * LPCWSTR pwszDll
    * LPCSTR pszOverrideFuncName


CryptRegisterOIDInfo
====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCRYPT_OID_INFO pInfo
    * DWORD dwFlags


CryptReleaseContext
===================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTPROV hProv
    * DWORD dwFlags


CryptRetrieveObjectByUrlA
=========================

Signature::

    * Library: cryptnet
    * Return value: BOOL

Parameters::

    * LPCSTR pszUrl
    * LPCSTR pszObjectOid
    * DWORD dwRetrievalFlags
    * DWORD dwTimeout
    * LPVOID *ppvObject
    * HCRYPTASYNC hAsyncRetrieve
    * PCRYPT_CREDENTIALS pCredentials
    * LPVOID pvVerify
    * PCRYPT_RETRIEVE_AUX_INFO pAuxInfo


CryptRetrieveObjectByUrlW
=========================

Signature::

    * Library: cryptnet
    * Return value: BOOL

Parameters::

    * LPCWSTR pszUrl
    * LPCSTR pszObjectOid
    * DWORD dwRetrievalFlags
    * DWORD dwTimeout
    * LPVOID *ppvObject
    * HCRYPTASYNC hAsyncRetrieve
    * PCRYPT_CREDENTIALS pCredentials
    * LPVOID pvVerify
    * PCRYPT_RETRIEVE_AUX_INFO pAuxInfo


CryptSetHashParam
=================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTHASH hHash
    * DWORD dwParam
    * const BYTE *pbData
    * DWORD dwFlags


CryptSetKeyIdentifierProperty
=============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * const CRYPT_HASH_BLOB *pKeyIdentifier
    * DWORD dwPropId
    * DWORD dwFlags
    * LPCWSTR pwszComputerName
    * void *pvReserved
    * const void *pvData


CryptSetKeyParam
================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTKEY hKey
    * DWORD dwParam
    * const BYTE *pbData
    * DWORD dwFlags


CryptSetOIDFunctionValue
========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwEncodingType
    * LPCSTR pszFuncName
    * LPCSTR pszOID
    * LPCWSTR pwszValueName
    * DWORD dwValueType
    * const BYTE *pbValueData
    * DWORD cbValueData


CryptSetProvParam
=================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTPROV hProv
    * DWORD dwParam
    * const BYTE *pbData
    * DWORD dwFlags


CryptSetProviderA
=================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * LPCSTR pszProvName
    * DWORD dwProvType


CryptSetProviderW
=================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * LPCWSTR pszProvName
    * DWORD dwProvType


CryptSignAndEncodeCertificate
=============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey
    * DWORD dwKeySpec
    * DWORD dwCertEncodingType
    * LPCSTR lpszStructType
    * const void *pvStructInfo
    * PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm
    * const void *pvHashAuxInfo
    * BYTE *pbEncoded
    * DWORD *pcbEncoded


CryptSignAndEncryptMessage
==========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_SIGN_MESSAGE_PARA pSignPara
    * PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara
    * DWORD cRecipientCert
    * PCCERT_CONTEXT rgpRecipientCert[]
    * const BYTE *pbToBeSignedAndEncrypted
    * DWORD cbToBeSignedAndEncrypted
    * BYTE *pbSignedAndEncryptedBlob
    * DWORD *pcbSignedAndEncryptedBlob


CryptSignCertificate
====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey
    * DWORD dwKeySpec
    * DWORD dwCertEncodingType
    * const BYTE *pbEncodedToBeSigned
    * DWORD cbEncodedToBeSigned
    * PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm
    * const void *pvHashAuxInfo
    * BYTE *pbSignature
    * DWORD *pcbSignature


CryptSignHashA
==============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTHASH hHash
    * DWORD dwKeySpec
    * LPCSTR szDescription
    * DWORD dwFlags
    * BYTE *pbSignature
    * DWORD *pdwSigLen


CryptSignHashW
==============

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTHASH hHash
    * DWORD dwKeySpec
    * LPCWSTR szDescription
    * DWORD dwFlags
    * BYTE *pbSignature
    * DWORD *pdwSigLen


CryptSignMessage
================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_SIGN_MESSAGE_PARA pSignPara
    * BOOL fDetachedSignature
    * DWORD cToBeSigned
    * const BYTE *rgpbToBeSigned[]
    * DWORD rgcbToBeSigned[]
    * BYTE *pbSignedBlob
    * DWORD *pcbSignedBlob


CryptSignMessageWithKey
=======================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_KEY_SIGN_MESSAGE_PARA pSignPara
    * const BYTE *pbToBeSigned
    * DWORD cbToBeSigned
    * BYTE *pbSignedBlob
    * DWORD *pcbSignedBlob


CryptStringToBinaryA
====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * LPCSTR pszString
    * DWORD cchString
    * DWORD dwFlags
    * BYTE *pbBinary
    * DWORD *pcbBinary
    * DWORD *pdwSkip
    * DWORD *pdwFlags


CryptStringToBinaryW
====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * LPCWSTR pszString
    * DWORD cchString
    * DWORD dwFlags
    * BYTE *pbBinary
    * DWORD *pcbBinary
    * DWORD *pdwSkip
    * DWORD *pdwFlags


CryptUIDlgCertMgr
=================

Signature::

    * Library: cryptui
    * Return value: BOOL

Parameters::

    * PCCRYPTUI_CERT_MGR_STRUCT pCryptUICertMgr


CryptUIDlgSelectCertificateFromStore
====================================

Signature::

    * Library: cryptui
    * Return value: PCCERT_CONTEXT

Parameters::

    * HCERTSTORE hCertStore
    * HWND hwnd
    * LPCWSTR pwszTitle
    * LPCWSTR pwszDisplayString
    * DWORD dwDontUseColumn
    * DWORD dwFlags
    * void *pvReserved


CryptUIDlgViewCertificateA
==========================

Signature::

    * Library: cryptui
    * Return value: BOOL

Parameters::

    * PCCRYPTUI_VIEWCERTIFICATE_STRUCTA pCertViewInfo
    * BOOL *pfPropertiesChanged


CryptUIDlgViewCertificateW
==========================

Signature::

    * Library: cryptui
    * Return value: BOOL

Parameters::

    * PCCRYPTUI_VIEWCERTIFICATE_STRUCTW pCertViewInfo
    * BOOL *pfPropertiesChanged


CryptUIDlgViewContext
=====================

Signature::

    * Library: cryptui
    * Return value: BOOL

Parameters::

    * DWORD dwContextType
    * const void *pvContext
    * HWND hwnd
    * LPCWSTR pwszTitle
    * DWORD dwFlags
    * void *pvReserved


CryptUIWizDigitalSign
=====================

Signature::

    * Library: cryptui
    * Return value: BOOL

Parameters::

    * DWORD dwFlags
    * HWND hwndParent
    * LPCWSTR pwszWizardTitle
    * PCCRYPTUI_WIZ_DIGITAL_SIGN_INFO pDigitalSignInfo
    * PCCRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT *ppSignContext


CryptUIWizExport
================

Signature::

    * Library: cryptui
    * Return value: BOOL

Parameters::

    * DWORD dwFlags
    * HWND hwndParent
    * LPCWSTR pwszWizardTitle
    * PCCRYPTUI_WIZ_EXPORT_INFO pExportInfo
    * void *pvoid


CryptUIWizFreeDigitalSignContext
================================

Signature::

    * Library: cryptui
    * Return value: BOOL

Parameters::

    * PCCRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT pSignContext


CryptUIWizImport
================

Signature::

    * Library: cryptui
    * Return value: BOOL

Parameters::

    * DWORD dwFlags
    * HWND hwndParent
    * LPCWSTR pwszWizardTitle
    * PCCRYPTUI_WIZ_IMPORT_SRC_INFO pImportSrc
    * HCERTSTORE hDestCertStore


CryptUninstallDefaultContext
============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTDEFAULTCONTEXT hDefaultContext
    * DWORD dwFlags
    * void *pvReserved


CryptUnprotectData
==================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DATA_BLOB *pDataIn
    * LPWSTR *ppszDataDescr
    * DATA_BLOB *pOptionalEntropy
    * PVOID pvReserved
    * CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct
    * DWORD dwFlags
    * DATA_BLOB *pDataOut


CryptUnprotectMemory
====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * LPVOID pDataIn
    * DWORD cbDataIn
    * DWORD dwFlags


CryptUnregisterDefaultOIDFunction
=================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwEncodingType
    * LPCSTR pszFuncName
    * LPCWSTR pwszDll


CryptUnregisterOIDFunction
==========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * DWORD dwEncodingType
    * LPCSTR pszFuncName
    * LPCSTR pszOID


CryptUnregisterOIDInfo
======================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCCRYPT_OID_INFO pInfo


CryptUpdateProtectedState
=========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PSID pOldSid
    * LPCWSTR pwszOldPassword
    * DWORD dwFlags
    * DWORD *pdwSuccessCount
    * DWORD *pdwFailureCount


CryptVerifyCertificateSignature
===============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV_LEGACY hCryptProv
    * DWORD dwCertEncodingType
    * const BYTE *pbEncoded
    * DWORD cbEncoded
    * PCERT_PUBLIC_KEY_INFO pPublicKey


CryptVerifyCertificateSignatureEx
=================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCRYPTPROV_LEGACY hCryptProv
    * DWORD dwCertEncodingType
    * DWORD dwSubjectType
    * void *pvSubject
    * DWORD dwIssuerType
    * void *pvIssuer
    * DWORD dwFlags
    * void *pvExtra


CryptVerifyDetachedMessageHash
==============================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_HASH_MESSAGE_PARA pHashPara
    * BYTE *pbDetachedHashBlob
    * DWORD cbDetachedHashBlob
    * DWORD cToBeHashed
    * const BYTE *rgpbToBeHashed[]
    * DWORD rgcbToBeHashed[]
    * BYTE *pbComputedHash
    * DWORD *pcbComputedHash


CryptVerifyDetachedMessageSignature
===================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara
    * DWORD dwSignerIndex
    * const BYTE *pbDetachedSignBlob
    * DWORD cbDetachedSignBlob
    * DWORD cToBeSigned
    * const BYTE *rgpbToBeSigned[]
    * DWORD rgcbToBeSigned[]
    * PCCERT_CONTEXT *ppSignerCert


CryptVerifyMessageHash
======================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_HASH_MESSAGE_PARA pHashPara
    * BYTE *pbHashedBlob
    * DWORD cbHashedBlob
    * BYTE *pbToBeHashed
    * DWORD *pcbToBeHashed
    * BYTE *pbComputedHash
    * DWORD *pcbComputedHash


CryptVerifyMessageSignature
===========================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara
    * DWORD dwSignerIndex
    * const BYTE *pbSignedBlob
    * DWORD cbSignedBlob
    * BYTE *pbDecoded
    * DWORD *pcbDecoded
    * PCCERT_CONTEXT *ppSignerCert


CryptVerifyMessageSignatureWithKey
==================================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * PCRYPT_KEY_VERIFY_MESSAGE_PARA pVerifyPara
    * PCERT_PUBLIC_KEY_INFO pPublicKeyInfo
    * const BYTE *pbSignedBlob
    * DWORD cbSignedBlob
    * BYTE *pbDecoded
    * DWORD *pcbDecoded


CryptVerifySignatureA
=====================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTHASH hHash
    * const BYTE *pbSignature
    * DWORD dwSigLen
    * HCRYPTKEY hPubKey
    * LPCSTR szDescription
    * DWORD dwFlags


CryptVerifySignatureW
=====================

Signature::

    * Library: cryptsp
    * Return value: BOOL

Parameters::

    * HCRYPTHASH hHash
    * const BYTE *pbSignature
    * DWORD dwSigLen
    * HCRYPTKEY hPubKey
    * LPCWSTR szDescription
    * DWORD dwFlags


CryptXmlEncode
==============

Signature::

    * Library: cryptxml
    * Return value: HRESULT

Parameters::

    * HCRYPTXML hCryptXml
    * CRYPT_XML_CHARSET dwCharset
    * const CRYPT_XML_PROPERTY *rgProperty
    * ULONG cProperty
    * void *pvCallbackState
    * PFN_CRYPT_XML_WRITE_CALLBACK pfnWrite


CryptXmlGetTransforms
=====================

Signature::

    * Library: cryptxml
    * Return value: HRESULT

Parameters::

    * const CRYPT_XML_TRANSFORM_CHAIN_CONFIG **ppConfig


CryptXmlOpenToDecode
====================

Signature::

    * Library: cryptxml
    * Return value: HRESULT

Parameters::

    * const CRYPT_XML_TRANSFORM_CHAIN_CONFIG *pConfig
    * DWORD dwFlags
    * const CRYPT_XML_PROPERTY *rgProperty
    * ULONG cProperty
    * const CRYPT_XML_BLOB *pEncoded
    * HCRYPTXML *phCryptXml


CryptXmlOpenToEncode
====================

Signature::

    * Library: cryptxml
    * Return value: HRESULT

Parameters::

    * const CRYPT_XML_TRANSFORM_CHAIN_CONFIG *pConfig
    * DWORD dwFlags
    * LPCWSTR wszId
    * const CRYPT_XML_PROPERTY *rgProperty
    * ULONG cProperty
    * const CRYPT_XML_BLOB *pEncoded
    * HCRYPTXML *phSignature


GetFriendlyNameOfCertA
======================

Signature::

    * Library: cryptdlg
    * Return value: DWORD

Parameters::

    * PCCERT_CONTEXT pccert
    * LPSTR pch
    * DWORD cch


GetFriendlyNameOfCertW
======================

Signature::

    * Library: cryptdlg
    * Return value: DWORD

Parameters::

    * PCCERT_CONTEXT pccert
    * LPWSTR pwch
    * DWORD cwch


PFXExportCertStore
==================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hStore
    * CRYPT_DATA_BLOB *pPFX
    * LPCWSTR szPassword
    * DWORD dwFlags


PFXExportCertStoreEx
====================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * HCERTSTORE hStore
    * CRYPT_DATA_BLOB *pPFX
    * LPCWSTR szPassword
    * void *pvPara
    * DWORD dwFlags


PFXImportCertStore
==================

Signature::

    * Library: crypt32
    * Return value: HCERTSTORE

Parameters::

    * CRYPT_DATA_BLOB *pPFX
    * LPCWSTR szPassword
    * DWORD dwFlags


PFXIsPFXBlob
============

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * CRYPT_DATA_BLOB *pPFX


PFXVerifyPassword
=================

Signature::

    * Library: crypt32
    * Return value: BOOL

Parameters::

    * CRYPT_DATA_BLOB *pPFX
    * LPCWSTR szPassword
    * DWORD dwFlags


WintrustSetDefaultIncludePEPageHashes
=====================================

Signature::

    * Library: wintrust
    * Return value: void

Parameters::

    * BOOL fIncludePEPageHashes


AddDllDirectory
===============

Signature::

    * Library: kernel32
    * Return value: DLL_DIRECTORY_COOKIE

Parameters::

    * PCWSTR NewDirectory


DisableThreadLibraryCalls
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HMODULE hLibModule


FreeLibrary
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HMODULE hLibModule


FreeLibraryAndExitThread
========================

Signature::

    * Library: kernel32
    * Return value: DECLSPEC_NORETURN

Parameters::

    * HMODULE hLibModule
    * DWORD dwExitCode


GetDllDirectoryA
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * DWORD nBufferLength
    * LPSTR lpBuffer


GetDllDirectoryW
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * DWORD nBufferLength
    * LPWSTR lpBuffer


GetModuleFileNameA
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * HMODULE hModule
    * LPSTR lpFilename
    * DWORD nSize


GetModuleFileNameW
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * HMODULE hModule
    * LPWSTR lpFilename
    * DWORD nSize


GetModuleFileNameExA
====================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    * HANDLE hProcess
    * HMODULE hModule
    * LPSTR lpFilename
    * DWORD nSize


GetModuleFileNameExW
====================

Signature::

    * Library: psapi
    * Return value: DWORD

Parameters::

    * HANDLE hProcess
    * HMODULE hModule
    * LPWSTR lpFilename
    * DWORD nSize


GetModuleHandleA
================

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    * LPCSTR lpModuleName


GetModuleHandleW
================

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    * LPCWSTR lpModuleName


GetModuleHandleExA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * DWORD dwFlags
    * LPCSTR lpModuleName
    * HMODULE *phModule


GetModuleHandleExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * DWORD dwFlags
    * LPCWSTR lpModuleName
    * HMODULE *phModule


GetProcAddress
==============

Signature::

    * Library: kernel32
    * Return value: FARPROC

Parameters::

    * HMODULE hModule
    * LPCSTR lpProcName


LoadLibraryA
============

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    * LPCSTR lpLibFileName


LoadLibraryW
============

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    * LPCWSTR lpLibFileName


LoadLibraryExA
==============

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    * LPCSTR lpLibFileName
    * HANDLE hFile
    * DWORD dwFlags


LoadLibraryExW
==============

Signature::

    * Library: kernel32
    * Return value: HMODULE

Parameters::

    * LPCWSTR lpLibFileName
    * HANDLE hFile
    * DWORD dwFlags


RemoveDllDirectory
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * DLL_DIRECTORY_COOKIE Cookie


SetDefaultDllDirectories
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * DWORD DirectoryFlags


SetDllDirectoryA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpPathName


SetDllDirectoryW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpPathName


AddUsersToEncryptedFile
=======================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpFileName
    * PENCRYPTION_CERTIFICATE_LIST pEncryptionCertificates


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

    * HANDLE hFile


CancelIoEx
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LPOVERLAPPED lpOverlapped


CancelSynchronousIo
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hThread


CheckNameLegalDOS8Dot3A
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpName
    * LPSTR lpOemName
    * DWORD OemNameSize
    * PBOOL pbNameContainsSpaces
    * PBOOL pbNameLegal


CheckNameLegalDOS8Dot3W
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpName
    * LPSTR lpOemName
    * DWORD OemNameSize
    * PBOOL pbNameContainsSpaces
    * PBOOL pbNameLegal


CloseEncryptedFileRaw
=====================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PVOID pvContext


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

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpExistingFileName
    * LPCWSTR lpNewFileName
    * BOOL bFailIfExists


CopyFileExA
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpExistingFileName
    * LPCSTR lpNewFileName
    * LPPROGRESS_ROUTINE lpProgressRoutine
    * LPVOID lpData
    * LPBOOL pbCancel
    * DWORD dwCopyFlags


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


CopyFileTransactedA
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpExistingFileName
    * LPCSTR lpNewFileName
    * LPPROGRESS_ROUTINE lpProgressRoutine
    * LPVOID lpData
    * LPBOOL pbCancel
    * DWORD dwCopyFlags
    * HANDLE hTransaction


CopyFileTransactedW
===================

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
    * HANDLE hTransaction


CreateDirectoryA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpPathName
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateDirectoryW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpPathName
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateDirectoryExA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpTemplateDirectory
    * LPCSTR lpNewDirectory
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateDirectoryExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpTemplateDirectory
    * LPCWSTR lpNewDirectory
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateDirectoryTransactedA
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpTemplateDirectory
    * LPCSTR lpNewDirectory
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * HANDLE hTransaction


CreateDirectoryTransactedW
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpTemplateDirectory
    * LPCWSTR lpNewDirectory
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * HANDLE hTransaction


CreateFileA
===========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPCSTR lpFileName
    * DWORD dwDesiredAccess
    * DWORD dwShareMode
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * DWORD dwCreationDisposition
    * DWORD dwFlagsAndAttributes
    * HANDLE hTemplateFile


CreateFileW
===========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPCWSTR lpFileName
    * DWORD dwDesiredAccess
    * DWORD dwShareMode
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * DWORD dwCreationDisposition
    * DWORD dwFlagsAndAttributes
    * HANDLE hTemplateFile


CreateFileTransactedA
=====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPCSTR lpFileName
    * DWORD dwDesiredAccess
    * DWORD dwShareMode
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * DWORD dwCreationDisposition
    * DWORD dwFlagsAndAttributes
    * HANDLE hTemplateFile
    * HANDLE hTransaction
    * PUSHORT pusMiniVersion
    * PVOID lpExtendedParameter


CreateFileTransactedW
=====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPCWSTR lpFileName
    * DWORD dwDesiredAccess
    * DWORD dwShareMode
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * DWORD dwCreationDisposition
    * DWORD dwFlagsAndAttributes
    * HANDLE hTemplateFile
    * HANDLE hTransaction
    * PUSHORT pusMiniVersion
    * PVOID lpExtendedParameter


CreateHardLinkA
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpFileName
    * LPCSTR lpExistingFileName
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateHardLinkW
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName
    * LPCWSTR lpExistingFileName
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes


CreateHardLinkTransactedA
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpFileName
    * LPCSTR lpExistingFileName
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * HANDLE hTransaction


CreateHardLinkTransactedW
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName
    * LPCWSTR lpExistingFileName
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * HANDLE hTransaction


CreateIoCompletionPort
======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * HANDLE FileHandle
    * HANDLE ExistingCompletionPort
    * ULONG_PTR CompletionKey
    * DWORD NumberOfConcurrentThreads


CreateSymbolicLinkA
===================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    * LPCSTR lpSymlinkFileName
    * LPCSTR lpTargetFileName
    * DWORD dwFlags


CreateSymbolicLinkW
===================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    * LPCWSTR lpSymlinkFileName
    * LPCWSTR lpTargetFileName
    * DWORD dwFlags


CreateSymbolicLinkTransactedA
=============================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    * LPCSTR lpSymlinkFileName
    * LPCSTR lpTargetFileName
    * DWORD dwFlags
    * HANDLE hTransaction


CreateSymbolicLinkTransactedW
=============================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    * LPCWSTR lpSymlinkFileName
    * LPCWSTR lpTargetFileName
    * DWORD dwFlags
    * HANDLE hTransaction


DecryptFileA
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR lpFileName
    * DWORD dwReserved


DecryptFileW
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName
    * DWORD dwReserved


DeleteFileA
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpFileName


DeleteFileW
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName


DeleteFileTransactedA
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpFileName
    * HANDLE hTransaction


DeleteFileTransactedW
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName
    * HANDLE hTransaction


DuplicateEncryptionInfoFile
===========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPCWSTR SrcFileName
    * LPCWSTR DstFileName
    * DWORD dwCreationDistribution
    * DWORD dwAttributes
    * const LPSECURITY_ATTRIBUTES lpSecurityAttributes


EncryptFileA
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR lpFileName


EncryptFileW
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName


EncryptionDisable
=================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR DirPath
    * BOOL Disable


FileEncryptionStatusA
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCSTR lpFileName
    * LPDWORD lpStatus


FileEncryptionStatusW
=====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName
    * LPDWORD lpStatus


FindClose
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFindFile


FindCloseChangeNotification
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hChangeHandle


FindFirstChangeNotificationA
============================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPCSTR lpPathName
    * BOOL bWatchSubtree
    * DWORD dwNotifyFilter


FindFirstChangeNotificationW
============================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPCWSTR lpPathName
    * BOOL bWatchSubtree
    * DWORD dwNotifyFilter


FindFirstFileA
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPCSTR lpFileName
    * LPWIN32_FIND_DATAA lpFindFileData


FindFirstFileW
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPCWSTR lpFileName
    * LPWIN32_FIND_DATAW lpFindFileData


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


FindFirstFileNameTransactedW
============================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPCWSTR lpFileName
    * DWORD dwFlags
    * LPDWORD StringLength
    * PWSTR LinkName
    * HANDLE hTransaction


FindFirstFileNameW
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPCWSTR lpFileName
    * DWORD dwFlags
    * LPDWORD StringLength
    * PWSTR LinkName


FindFirstFileTransactedA
========================

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
    * HANDLE hTransaction


FindFirstFileTransactedW
========================

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
    * HANDLE hTransaction


FindFirstStreamTransactedW
==========================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPCWSTR lpFileName
    * STREAM_INFO_LEVELS InfoLevel
    * LPVOID lpFindStreamData
    * DWORD dwFlags
    * HANDLE hTransaction


FindFirstStreamW
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPCWSTR lpFileName
    * STREAM_INFO_LEVELS InfoLevel
    * LPVOID lpFindStreamData
    * DWORD dwFlags


FindNextChangeNotification
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hChangeHandle


FindNextFileA
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFindFile
    * LPWIN32_FIND_DATAA lpFindFileData


FindNextFileW
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFindFile
    * LPWIN32_FIND_DATAW lpFindFileData


FindNextFileNameW
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFindStream
    * LPDWORD StringLength
    * PWSTR LinkName


FindNextStreamW
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFindStream
    * LPVOID lpFindStreamData


FlushFileBuffers
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile


FreeEncryptionCertificateHashList
=================================

Signature::

    * Library: advapi32
    * Return value: void

Parameters::

    * PENCRYPTION_CERTIFICATE_HASH_LIST pUsers


GetBinaryTypeA
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpApplicationName
    * LPDWORD lpBinaryType


GetBinaryTypeW
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpApplicationName
    * LPDWORD lpBinaryType


GetCompressedFileSizeA
======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCSTR lpFileName
    * LPDWORD lpFileSizeHigh


GetCompressedFileSizeW
======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpFileName
    * LPDWORD lpFileSizeHigh


GetCompressedFileSizeTransactedA
================================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCSTR lpFileName
    * LPDWORD lpFileSizeHigh
    * HANDLE hTransaction


GetCompressedFileSizeTransactedW
================================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpFileName
    * LPDWORD lpFileSizeHigh
    * HANDLE hTransaction


GetCurrentDirectoryA
====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * DWORD nBufferLength
    * LPSTR lpBuffer


GetCurrentDirectoryW
====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * DWORD nBufferLength
    * LPWSTR lpBuffer


GetFileAttributesA
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCSTR lpFileName


GetFileAttributesW
==================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpFileName


GetFileAttributesExA
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpFileName
    * GET_FILEEX_INFO_LEVELS fInfoLevelId
    * LPVOID lpFileInformation


GetFileAttributesExW
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName
    * GET_FILEEX_INFO_LEVELS fInfoLevelId
    * LPVOID lpFileInformation


GetFileAttributesTransactedA
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpFileName
    * GET_FILEEX_INFO_LEVELS fInfoLevelId
    * LPVOID lpFileInformation
    * HANDLE hTransaction


GetFileAttributesTransactedW
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName
    * GET_FILEEX_INFO_LEVELS fInfoLevelId
    * LPVOID lpFileInformation
    * HANDLE hTransaction


GetFileBandwidthReservation
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LPDWORD lpPeriodMilliseconds
    * LPDWORD lpBytesPerPeriod
    * LPBOOL pDiscardable
    * LPDWORD lpTransferSize
    * LPDWORD lpNumOutstandingRequests


GetFileInformationByHandle
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LPBY_HANDLE_FILE_INFORMATION lpFileInformation


GetFileInformationByHandleEx
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * FILE_INFO_BY_HANDLE_CLASS FileInformationClass
    * LPVOID lpFileInformation
    * DWORD dwBufferSize


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

    * Library: kernel32
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


GetFinalPathNameByHandleA
=========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * HANDLE hFile
    * LPSTR lpszFilePath
    * DWORD cchFilePath
    * DWORD dwFlags


GetFinalPathNameByHandleW
=========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * HANDLE hFile
    * LPWSTR lpszFilePath
    * DWORD cchFilePath
    * DWORD dwFlags


GetFullPathNameA
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCSTR lpFileName
    * DWORD nBufferLength
    * LPSTR lpBuffer
    * LPSTR *lpFilePart


GetFullPathNameW
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpFileName
    * DWORD nBufferLength
    * LPWSTR lpBuffer
    * LPWSTR *lpFilePart


GetFullPathNameTransactedA
==========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCSTR lpFileName
    * DWORD nBufferLength
    * LPSTR lpBuffer
    * LPSTR *lpFilePart
    * HANDLE hTransaction


GetFullPathNameTransactedW
==========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpFileName
    * DWORD nBufferLength
    * LPWSTR lpBuffer
    * LPWSTR *lpFilePart
    * HANDLE hTransaction


GetLongPathNameA
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCSTR lpszShortPath
    * LPSTR lpszLongPath
    * DWORD cchBuffer


GetLongPathNameW
================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpszShortPath
    * LPWSTR lpszLongPath
    * DWORD cchBuffer


GetLongPathNameTransactedA
==========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCSTR lpszShortPath
    * LPSTR lpszLongPath
    * DWORD cchBuffer
    * HANDLE hTransaction


GetLongPathNameTransactedW
==========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpszShortPath
    * LPWSTR lpszLongPath
    * DWORD cchBuffer
    * HANDLE hTransaction


GetQueuedCompletionStatus
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE CompletionPort
    * LPDWORD lpNumberOfBytesTransferred
    * PULONG_PTR lpCompletionKey
    * LPOVERLAPPED *lpOverlapped
    * DWORD dwMilliseconds


GetQueuedCompletionStatusEx
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE CompletionPort
    * LPOVERLAPPED_ENTRY lpCompletionPortEntries
    * ULONG ulCount
    * PULONG ulNumEntriesRemoved
    * DWORD dwMilliseconds
    * BOOL fAlertable


GetShortPathNameA
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCSTR lpszLongPath
    * LPSTR lpszShortPath
    * DWORD cchBuffer


GetShortPathNameW
=================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpszLongPath
    * LPWSTR lpszShortPath
    * DWORD cchBuffer


GetTempFileNameA
================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    * LPCSTR lpPathName
    * LPCSTR lpPrefixString
    * UINT uUnique
    * LPSTR lpTempFileName


GetTempFileNameW
================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    * LPCWSTR lpPathName
    * LPCWSTR lpPrefixString
    * UINT uUnique
    * LPWSTR lpTempFileName


GetTempPathA
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * DWORD nBufferLength
    * LPSTR lpBuffer


GetTempPathW
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * DWORD nBufferLength
    * LPWSTR lpBuffer


LockFile
========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * DWORD dwFileOffsetLow
    * DWORD dwFileOffsetHigh
    * DWORD nNumberOfBytesToLockLow
    * DWORD nNumberOfBytesToLockHigh


LockFileEx
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * DWORD dwFlags
    * DWORD dwReserved
    * DWORD nNumberOfBytesToLockLow
    * DWORD nNumberOfBytesToLockHigh
    * LPOVERLAPPED lpOverlapped


MoveFileA
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpExistingFileName
    * LPCSTR lpNewFileName


MoveFileW
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpExistingFileName
    * LPCWSTR lpNewFileName


MoveFileExA
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpExistingFileName
    * LPCSTR lpNewFileName
    * DWORD dwFlags


MoveFileExW
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpExistingFileName
    * LPCWSTR lpNewFileName
    * DWORD dwFlags


MoveFileTransactedA
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpExistingFileName
    * LPCSTR lpNewFileName
    * LPPROGRESS_ROUTINE lpProgressRoutine
    * LPVOID lpData
    * DWORD dwFlags
    * HANDLE hTransaction


MoveFileTransactedW
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpExistingFileName
    * LPCWSTR lpNewFileName
    * LPPROGRESS_ROUTINE lpProgressRoutine
    * LPVOID lpData
    * DWORD dwFlags
    * HANDLE hTransaction


MoveFileWithProgressA
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpExistingFileName
    * LPCSTR lpNewFileName
    * LPPROGRESS_ROUTINE lpProgressRoutine
    * LPVOID lpData
    * DWORD dwFlags


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


OpenEncryptedFileRawA
=====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPCSTR lpFileName
    * ULONG ulFlags
    * PVOID *pvContext


OpenEncryptedFileRawW
=====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpFileName
    * ULONG ulFlags
    * PVOID *pvContext


OpenFile
========

Signature::

    * Library: kernel32
    * Return value: HFILE

Parameters::

    * LPCSTR lpFileName
    * LPOFSTRUCT lpReOpenBuff
    * UINT uStyle


OpenFileById
============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * HANDLE hVolumeHint
    * LPFILE_ID_DESCRIPTOR lpFileId
    * DWORD dwDesiredAccess
    * DWORD dwShareMode
    * LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * DWORD dwFlagsAndAttributes


PostQueuedCompletionStatus
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE CompletionPort
    * DWORD dwNumberOfBytesTransferred
    * ULONG_PTR dwCompletionKey
    * LPOVERLAPPED lpOverlapped


QueryRecoveryAgentsOnEncryptedFile
==================================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpFileName
    * PENCRYPTION_CERTIFICATE_HASH_LIST *pRecoveryAgents


QueryUsersOnEncryptedFile
=========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpFileName
    * PENCRYPTION_CERTIFICATE_HASH_LIST *pUsers


ReOpenFile
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * HANDLE hOriginalFile
    * DWORD dwDesiredAccess
    * DWORD dwShareMode
    * DWORD dwFlagsAndAttributes


ReadDirectoryChangesW
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hDirectory
    * LPVOID lpBuffer
    * DWORD nBufferLength
    * BOOL bWatchSubtree
    * DWORD dwNotifyFilter
    * LPDWORD lpBytesReturned
    * LPOVERLAPPED lpOverlapped
    * LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


ReadEncryptedFileRaw
====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PFE_EXPORT_FUNC pfExportCallback
    * PVOID pvCallbackContext
    * PVOID pvContext


ReadFile
========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LPVOID lpBuffer
    * DWORD nNumberOfBytesToRead
    * LPDWORD lpNumberOfBytesRead
    * LPOVERLAPPED lpOverlapped


ReadFileEx
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LPVOID lpBuffer
    * DWORD nNumberOfBytesToRead
    * LPOVERLAPPED lpOverlapped
    * LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


ReadFileScatter
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * FILE_SEGMENT_ELEMENT aSegmentArray[]
    * DWORD nNumberOfBytesToRead
    * LPDWORD lpReserved
    * LPOVERLAPPED lpOverlapped


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

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpPathName


RemoveDirectoryTransactedA
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpPathName
    * HANDLE hTransaction


RemoveDirectoryTransactedW
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpPathName
    * HANDLE hTransaction


RemoveUsersFromEncryptedFile
============================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpFileName
    * PENCRYPTION_CERTIFICATE_HASH_LIST pHashes


ReplaceFileA
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpReplacedFileName
    * LPCSTR lpReplacementFileName
    * LPCSTR lpBackupFileName
    * DWORD dwReplaceFlags
    * LPVOID lpExclude
    * LPVOID lpReserved


ReplaceFileW
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpReplacedFileName
    * LPCWSTR lpReplacementFileName
    * LPCWSTR lpBackupFileName
    * DWORD dwReplaceFlags
    * LPVOID lpExclude
    * LPVOID lpReserved


SearchPathA
===========

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCSTR lpPath
    * LPCSTR lpFileName
    * LPCSTR lpExtension
    * DWORD nBufferLength
    * LPSTR lpBuffer
    * LPSTR *lpFilePart


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


SetCurrentDirectoryA
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpPathName


SetCurrentDirectoryW
====================

Signature::

    * Library: kernel32
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

    * LPCSTR lpFileName
    * DWORD dwFileAttributes


SetFileAttributesW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName
    * DWORD dwFileAttributes


SetFileAttributesTransactedA
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpFileName
    * DWORD dwFileAttributes
    * HANDLE hTransaction


SetFileAttributesTransactedW
============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpFileName
    * DWORD dwFileAttributes
    * HANDLE hTransaction


SetFileBandwidthReservation
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * DWORD nPeriodMilliseconds
    * DWORD nBytesPerPeriod
    * BOOL bDiscardable
    * LPDWORD lpTransferSize
    * LPDWORD lpNumOutstandingRequests


SetFileCompletionNotificationModes
==================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE FileHandle
    * UCHAR Flags


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


SetFileIoOverlappedRange
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE FileHandle
    * PUCHAR OverlappedRangeStart
    * ULONG Length


SetFilePointer
==============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * HANDLE hFile
    * LONG lDistanceToMove
    * PLONG lpDistanceToMoveHigh
    * DWORD dwMoveMethod


SetFilePointerEx
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LARGE_INTEGER liDistanceToMove
    * PLARGE_INTEGER lpNewFilePointer
    * DWORD dwMoveMethod


SetFileShortNameA
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LPCSTR lpShortName


SetFileShortNameW
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LPCWSTR lpShortName


SetFileValidData
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LONGLONG ValidDataLength


SetSearchPathMode
=================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * DWORD Flags


SetUserFileEncryptionKey
========================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PENCRYPTION_CERTIFICATE pEncryptionCertificate


UnlockFile
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * DWORD dwFileOffsetLow
    * DWORD dwFileOffsetHigh
    * DWORD nNumberOfBytesToUnlockLow
    * DWORD nNumberOfBytesToUnlockHigh


UnlockFileEx
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * DWORD dwReserved
    * DWORD nNumberOfBytesToUnlockLow
    * DWORD nNumberOfBytesToUnlockHigh
    * LPOVERLAPPED lpOverlapped


Wow64DisableWow64FsRedirection
==============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * PVOID *OldValue


Wow64EnableWow64FsRedirection
=============================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    * BOOLEAN Wow64FsEnableRedirection


Wow64RevertWow64FsRedirection
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * PVOID OlValue


WriteEncryptedFileRaw
=====================

Signature::

    * Library: advapi32
    * Return value: DWORD

Parameters::

    * PFE_IMPORT_FUNC pfImportCallback
    * PVOID pvCallbackContext
    * PVOID pvContext


WriteFile
=========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LPCVOID lpBuffer
    * DWORD nNumberOfBytesToWrite
    * LPDWORD lpNumberOfBytesWritten
    * LPOVERLAPPED lpOverlapped


WriteFileEx
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LPCVOID lpBuffer
    * DWORD nNumberOfBytesToWrite
    * LPOVERLAPPED lpOverlapped
    * LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


WriteFileGather
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * FILE_SEGMENT_ELEMENT aSegmentArray[]
    * DWORD nNumberOfBytesToWrite
    * LPDWORD lpReserved
    * LPOVERLAPPED lpOverlapped


CallMsgFilterA
==============

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    * LPMSG lpMsg
    * int nCode


CallMsgFilterW
==============

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    * LPMSG lpMsg
    * int nCode


CallNextHookEx
==============

Signature::

    * Library: user32
    * Return value: LRESULT

Parameters::

    * HHOOK hhk
    * int nCode
    * WPARAM wParam
    * LPARAM lParam


SetWindowsHookExA
=================

Signature::

    * Library: user32
    * Return value: HHOOK

Parameters::

    * int idHook
    * HOOKPROC lpfn
    * HINSTANCE hmod
    * DWORD dwThreadId


SetWindowsHookExW
=================

Signature::

    * Library: user32
    * Return value: HHOOK

Parameters::

    * int idHook
    * HOOKPROC lpfn
    * HINSTANCE hmod
    * DWORD dwThreadId


UnhookWindowsHookEx
===================

Signature::

    * Library: user32
    * Return value: BOOL

Parameters::

    * HHOOK hhk


CommitUrlCacheEntryA
====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCSTR lpszUrlName
    * LPCSTR lpszLocalFileName
    * FILETIME ExpireTime
    * FILETIME LastModifiedTime
    * DWORD CacheEntryType
    * LPBYTE lpHeaderInfo
    * DWORD cchHeaderInfo
    * LPCSTR lpszFileExtension
    * LPCSTR lpszOriginalUrl


CommitUrlCacheEntryW
====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCWSTR lpszUrlName
    * LPCWSTR lpszLocalFileName
    * FILETIME ExpireTime
    * FILETIME LastModifiedTime
    * DWORD CacheEntryType
    * LPWSTR lpszHeaderInfo
    * DWORD cchHeaderInfo
    * LPCWSTR lpszFileExtension
    * LPCWSTR lpszOriginalUrl


DnsFree
=======

Signature::

    * Library: dnsapi
    * Return value: void

Parameters::

    * PVOID pData
    * DNS_FREE_TYPE FreeType


DnsFreeProxyName
================

Signature::

    * Library: dnsapi
    * Return value: void

Parameters::

    * PWSTR proxyName


DnsGetProxyInformation
======================

Signature::

    * Library: dnsapi
    * Return value: DWORD

Parameters::

    * PCWSTR hostName
    * DNS_PROXY_INFORMATION *proxyInformation
    * DNS_PROXY_INFORMATION *defaultProxyInformation
    * DNS_PROXY_COMPLETION_ROUTINE completionRoutine
    * void *completionContext


DnsQueryConfig
==============

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    * DNS_CONFIG_TYPE Config
    * DWORD Flag
    * PCWSTR pwsAdapterName
    * PVOID pReserved
    * PVOID pBuffer
    * PDWORD pBufLen


DnsRecordCompare
================

Signature::

    * Library: dnsapi
    * Return value: BOOL

Parameters::

    * PDNS_RECORD pRecord1
    * PDNS_RECORD pRecord2


DnsRecordCopyEx
===============

Signature::

    * Library: dnsapi
    * Return value: PDNS_RECORD

Parameters::

    * PDNS_RECORD pRecord
    * DNS_CHARSET CharSetIn
    * DNS_CHARSET CharSetOut


DnsRecordListFree
=================

Signature::

    * Library: dnsapi
    * Return value: void

Parameters::

    * PDNS_RECORD pRecordList
    * DNS_FREE_TYPE FreeType


DnsRecordSetCompare
===================

Signature::

    * Library: dnsapi
    * Return value: BOOL

Parameters::

    * PDNS_RECORD pRR1
    * PDNS_RECORD pRR2
    * PDNS_RECORD *ppDiff1
    * PDNS_RECORD *ppDiff2


DnsRecordSetCopyEx
==================

Signature::

    * Library: dnsapi
    * Return value: PDNS_RECORD

Parameters::

    * PDNS_RECORD pRecordSet
    * DNS_CHARSET CharSetIn
    * DNS_CHARSET CharSetOut


DnsReleaseContextHandle
=======================

Signature::

    * Library: dnsapi
    * Return value: void

Parameters::

    * HANDLE hContext


DnsReplaceRecordSetA
====================

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    * PDNS_RECORD pReplaceSet
    * DWORD Options
    * HANDLE hContext
    * PVOID pExtraInfo
    * PVOID pReserved


DnsReplaceRecordSetW
====================

Signature::

    * Library: dnsapi
    * Return value: DNS_STATUS

Parameters::

    * PDNS_RECORD pReplaceSet
    * DWORD Options
    * HANDLE hContext
    * PVOID pExtraInfo
    * PVOID pReserved


FindNextUrlCacheEntryA
======================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * HANDLE hEnumHandle
    * LPINTERNET_CACHE_ENTRY_INFOA lpNextCacheEntryInfo
    * LPDWORD lpcbCacheEntryInfo


FindNextUrlCacheEntryW
======================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * HANDLE hEnumHandle
    * LPINTERNET_CACHE_ENTRY_INFOW lpNextCacheEntryInfo
    * LPDWORD lpcbCacheEntryInfo


FindNextUrlCacheEntryExA
========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * HANDLE hEnumHandle
    * LPINTERNET_CACHE_ENTRY_INFOA lpNextCacheEntryInfo
    * LPDWORD lpcbCacheEntryInfo
    * LPVOID lpGroupAttributes
    * LPDWORD lpcbGroupAttributes
    * LPVOID lpReserved


FindNextUrlCacheEntryExW
========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * HANDLE hEnumHandle
    * LPINTERNET_CACHE_ENTRY_INFOW lpNextCacheEntryInfo
    * LPDWORD lpcbCacheEntryInfo
    * LPVOID lpGroupAttributes
    * LPDWORD lpcbGroupAttributes
    * LPVOID lpReserved


FreeAddrInfoEx
==============

Signature::

    * Library: ws2_32
    * Return value: void

Parameters::

    * PADDRINFOEXA pAddrInfoEx


FreeAddrInfoExW
===============

Signature::

    * Library: ws2_32
    * Return value: void

Parameters::

    * PADDRINFOEXW pAddrInfoEx


FreeAddrInfoW
=============

Signature::

    * Library: ws2_32
    * Return value: void

Parameters::

    * PADDRINFOW pAddrInfo


GetAddrInfoExA
==============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * PCSTR pName
    * PCSTR pServiceName
    * DWORD dwNameSpace
    * LPGUID lpNspId
    * const ADDRINFOEXA *hints
    * PADDRINFOEXA *ppResult
    * struct timeval *timeout
    * LPOVERLAPPED lpOverlapped
    * LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine
    * LPHANDLE lpNameHandle


GetAddrInfoExW
==============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * PCWSTR pName
    * PCWSTR pServiceName
    * DWORD dwNameSpace
    * LPGUID lpNspId
    * const ADDRINFOEXW *hints
    * PADDRINFOEXW *ppResult
    * struct timeval *timeout
    * LPOVERLAPPED lpOverlapped
    * LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine
    * LPHANDLE lpHandle


GetAddrInfoW
============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * PCWSTR pNodeName
    * PCWSTR pServiceName
    * const ADDRINFOW *pHints
    * PADDRINFOW *ppResult


GetNameInfoW
============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * const SOCKADDR *pSockaddr
    * socklen_t SockaddrLength
    * PWCHAR pNodeBuffer
    * DWORD NodeBufferSize
    * PWCHAR pServiceBuffer
    * DWORD ServiceBufferSize
    * INT Flags


GetUrlCacheEntryInfoA
=====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCSTR lpszUrlName
    * LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo
    * LPDWORD lpcbCacheEntryInfo


GetUrlCacheEntryInfoW
=====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCWSTR lpszUrlName
    * LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo
    * LPDWORD lpcbCacheEntryInfo


GetUrlCacheEntryInfoExA
=======================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCSTR lpszUrl
    * LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo
    * LPDWORD lpcbCacheEntryInfo
    * LPSTR lpszRedirectUrl
    * LPDWORD lpcbRedirectUrl
    * LPVOID lpReserved
    * DWORD dwFlags


GetUrlCacheEntryInfoExW
=======================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCWSTR lpszUrl
    * LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo
    * LPDWORD lpcbCacheEntryInfo
    * LPWSTR lpszRedirectUrl
    * LPDWORD lpcbRedirectUrl
    * LPVOID lpReserved
    * DWORD dwFlags


HttpAddFragmentToCache
======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ReqQueueHandle
    * PCWSTR pUrlPrefix
    * PHTTP_DATA_CHUNK pDataChunk
    * PHTTP_CACHE_POLICY pCachePolicy
    * LPOVERLAPPED pOverlapped


HttpAddUrl
==========

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ReqQueueHandle
    * PCWSTR pFullyQualifiedUrl
    * PVOID pReserved


HttpAddUrlToUrlGroup
====================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HTTP_URL_GROUP_ID UrlGroupId
    * PCWSTR pFullyQualifiedUrl
    * HTTP_URL_CONTEXT UrlContext
    * ULONG Reserved


HttpCloseRequestQueue
=====================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ReqQueueHandle


HttpCloseServerSession
======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HTTP_SERVER_SESSION_ID ServerSessionId


HttpCloseUrlGroup
=================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HTTP_URL_GROUP_ID UrlGroupId


HttpCreateHttpHandle
====================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * PHANDLE pReqQueueHandle
    * ULONG Reserved


HttpCreateRequestQueue
======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HTTPAPI_VERSION Version
    * PCWSTR pName
    * PSECURITY_ATTRIBUTES pSecurityAttributes
    * ULONG Flags
    * PHANDLE pReqQueueHandle


HttpCreateServerSession
=======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HTTPAPI_VERSION Version
    * PHTTP_SERVER_SESSION_ID pServerSessionId
    * ULONG Reserved


HttpCreateUrlGroup
==================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HTTP_SERVER_SESSION_ID ServerSessionId
    * PHTTP_URL_GROUP_ID pUrlGroupId
    * ULONG Reserved


HttpDeleteServiceConfiguration
==============================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ServiceHandle
    * HTTP_SERVICE_CONFIG_ID ConfigId
    * PVOID pConfigInformation
    * ULONG ConfigInformationLength
    * LPOVERLAPPED pOverlapped


HttpFlushResponseCache
======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ReqQueueHandle
    * PCWSTR pUrlPrefix
    * ULONG Flags
    * LPOVERLAPPED pOverlapped


HttpInitialize
==============

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HTTPAPI_VERSION Version
    * ULONG Flags
    * PVOID pReserved


HttpQueryInfoA
==============

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * HINTERNET hRequest
    * DWORD dwInfoLevel
    * LPVOID lpBuffer
    * LPDWORD lpdwBufferLength
    * LPDWORD lpdwIndex


HttpQueryInfoW
==============

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * HINTERNET hRequest
    * DWORD dwInfoLevel
    * LPVOID lpBuffer
    * LPDWORD lpdwBufferLength
    * LPDWORD lpdwIndex


HttpQueryRequestQueueProperty
=============================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE Handle
    * HTTP_SERVER_PROPERTY Property
    * PVOID pPropertyInformation
    * ULONG PropertyInformationLength
    * ULONG Reserved
    * PULONG pReturnLength
    * PVOID pReserved


HttpQueryServerSessionProperty
==============================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HTTP_SERVER_SESSION_ID ServerSessionId
    * HTTP_SERVER_PROPERTY Property
    * PVOID pPropertyInformation
    * ULONG PropertyInformationLength
    * PULONG pReturnLength


HttpQueryServiceConfiguration
=============================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ServiceHandle
    * HTTP_SERVICE_CONFIG_ID ConfigId
    * PVOID pInput
    * ULONG InputLength
    * PVOID pOutput
    * ULONG OutputLength
    * PULONG pReturnLength
    * LPOVERLAPPED pOverlapped


HttpQueryUrlGroupProperty
=========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HTTP_URL_GROUP_ID UrlGroupId
    * HTTP_SERVER_PROPERTY Property
    * PVOID pPropertyInformation
    * ULONG PropertyInformationLength
    * PULONG pReturnLength


HttpReadFragmentFromCache
=========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ReqQueueHandle
    * PCWSTR pUrlPrefix
    * PHTTP_BYTE_RANGE pByteRange
    * PVOID pBuffer
    * ULONG BufferLength
    * PULONG pBytesRead
    * LPOVERLAPPED pOverlapped


HttpReceiveClientCertificate
============================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ReqQueueHandle
    * HTTP_CONNECTION_ID ConnectionId
    * ULONG Flags
    * PHTTP_SSL_CLIENT_CERT_INFO pSslClientCertInfo
    * ULONG SslClientCertInfoSize
    * PULONG pBytesReceived
    * LPOVERLAPPED pOverlapped


HttpReceiveHttpRequest
======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ReqQueueHandle
    * HTTP_REQUEST_ID RequestId
    * ULONG Flags
    * PHTTP_REQUEST pRequestBuffer
    * ULONG RequestBufferLength
    * PULONG pBytesReturned
    * LPOVERLAPPED pOverlapped


HttpReceiveRequestEntityBody
============================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ReqQueueHandle
    * HTTP_REQUEST_ID RequestId
    * ULONG Flags
    * PVOID pBuffer
    * ULONG EntityBufferLength
    * PULONG pBytesReturned
    * LPOVERLAPPED pOverlapped


HttpRemoveUrl
=============

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ReqQueueHandle
    * PCWSTR pFullyQualifiedUrl


HttpRemoveUrlFromUrlGroup
=========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HTTP_URL_GROUP_ID UrlGroupId
    * PCWSTR pFullyQualifiedUrl
    * ULONG Flags


HttpSendHttpResponse
====================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ReqQueueHandle
    * HTTP_REQUEST_ID RequestId
    * ULONG Flags
    * PHTTP_RESPONSE pHttpResponse
    * PHTTP_CACHE_POLICY pCachePolicy
    * PULONG pBytesSent
    * PVOID pReserved1
    * ULONG Reserved2
    * LPOVERLAPPED pOverlapped
    * PHTTP_LOG_DATA pLogData


HttpSendResponseEntityBody
==========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ReqQueueHandle
    * HTTP_REQUEST_ID RequestId
    * ULONG Flags
    * USHORT EntityChunkCount
    * PHTTP_DATA_CHUNK pEntityChunks
    * PULONG pBytesSent
    * PVOID pReserved1
    * ULONG Reserved2
    * LPOVERLAPPED pOverlapped
    * PHTTP_LOG_DATA pLogData


HttpSetRequestQueueProperty
===========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE Handle
    * HTTP_SERVER_PROPERTY Property
    * PVOID pPropertyInformation
    * ULONG PropertyInformationLength
    * ULONG Reserved
    * PVOID pReserved


HttpSetServerSessionProperty
============================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HTTP_SERVER_SESSION_ID ServerSessionId
    * HTTP_SERVER_PROPERTY Property
    * PVOID pPropertyInformation
    * ULONG PropertyInformationLength


HttpSetServiceConfiguration
===========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ServiceHandle
    * HTTP_SERVICE_CONFIG_ID ConfigId
    * PVOID pConfigInformation
    * ULONG ConfigInformationLength
    * LPOVERLAPPED pOverlapped


HttpSetUrlGroupProperty
=======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HTTP_URL_GROUP_ID UrlGroupId
    * HTTP_SERVER_PROPERTY Property
    * PVOID pPropertyInformation
    * ULONG PropertyInformationLength


HttpShutdownRequestQueue
========================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ReqQueueHandle


HttpTerminate
=============

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * ULONG Flags
    * PVOID pReserved


HttpWaitForDemandStart
======================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ReqQueueHandle
    * LPOVERLAPPED pOverlapped


HttpWaitForDisconnect
=====================

Signature::

    * Library: httpapi
    * Return value: ULONG

Parameters::

    * HANDLE ReqQueueHandle
    * HTTP_CONNECTION_ID ConnectionId
    * LPOVERLAPPED pOverlapped


IcmpCloseHandle
===============

Signature::

    * Library: icmp
    * Return value: BOOL

Parameters::

    * HANDLE IcmpHandle


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

    * LPVOID ReplyBuffer
    * DWORD ReplySize


IcmpSendEcho
============

Signature::

    * Library: icmp
    * Return value: DWORD

Parameters::

    * HANDLE IcmpHandle
    * IPAddr DestinationAddress
    * LPVOID RequestData
    * WORD RequestSize
    * PIP_OPTION_INFORMATION RequestOptions
    * LPVOID ReplyBuffer
    * DWORD ReplySize
    * DWORD Timeout


InetNtopW
=========

Signature::

    * Library: ws2_32
    * Return value: PCWSTR

Parameters::

    * INT Family
    * PVOID pAddr
    * PWSTR pStringBuf
    * size_t StringBufSize


InetPtonW
=========

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * INT Family
    * PCWSTR pszAddrString
    * PVOID pAddrBuf


InternetCanonicalizeUrlA
========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCSTR lpszUrl
    * LPSTR lpszBuffer
    * LPDWORD lpdwBufferLength
    * DWORD dwFlags


InternetCanonicalizeUrlW
========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCWSTR lpszUrl
    * LPWSTR lpszBuffer
    * LPDWORD lpdwBufferLength
    * DWORD dwFlags


InternetCheckConnectionA
========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCSTR lpszUrl
    * DWORD dwFlags
    * DWORD dwReserved


InternetCheckConnectionW
========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCWSTR lpszUrl
    * DWORD dwFlags
    * DWORD dwReserved


InternetCombineUrlA
===================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCSTR lpszBaseUrl
    * LPCSTR lpszRelativeUrl
    * LPSTR lpszBuffer
    * LPDWORD lpdwBufferLength
    * DWORD dwFlags


InternetCombineUrlW
===================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCWSTR lpszBaseUrl
    * LPCWSTR lpszRelativeUrl
    * LPWSTR lpszBuffer
    * LPDWORD lpdwBufferLength
    * DWORD dwFlags


InternetCrackUrlA
=================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCSTR lpszUrl
    * DWORD dwUrlLength
    * DWORD dwFlags
    * LPURL_COMPONENTSA lpUrlComponents


InternetCrackUrlW
=================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCWSTR lpszUrl
    * DWORD dwUrlLength
    * DWORD dwFlags
    * LPURL_COMPONENTSW lpUrlComponents


InternetCreateUrlA
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPURL_COMPONENTSA lpUrlComponents
    * DWORD dwFlags
    * LPSTR lpszUrl
    * LPDWORD lpdwUrlLength


InternetCreateUrlW
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPURL_COMPONENTSW lpUrlComponents
    * DWORD dwFlags
    * LPWSTR lpszUrl
    * LPDWORD lpdwUrlLength


InternetGetConnectedStateExA
============================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPDWORD lpdwFlags
    * LPSTR lpszConnectionName
    * DWORD cchNameLen
    * DWORD dwReserved


InternetGetConnectedStateExW
============================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPDWORD lpdwFlags
    * LPWSTR lpszConnectionName
    * DWORD cchNameLen
    * DWORD dwReserved


InternetGetCookieA
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCSTR lpszUrl
    * LPCSTR lpszCookieName
    * LPSTR lpszCookieData
    * LPDWORD lpdwSize


InternetGetCookieW
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCWSTR lpszUrl
    * LPCWSTR lpszCookieName
    * LPWSTR lpszCookieData
    * LPDWORD lpdwSize


InternetGetCookieExA
====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCSTR lpszUrl
    * LPCSTR lpszCookieName
    * LPSTR lpszCookieData
    * LPDWORD lpdwSize
    * DWORD dwFlags
    * LPVOID lpReserved


InternetGetCookieExW
====================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCWSTR lpszUrl
    * LPCWSTR lpszCookieName
    * LPWSTR lpszCookieData
    * LPDWORD lpdwSize
    * DWORD dwFlags
    * LPVOID lpReserved


InternetGetLastResponseInfoA
============================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPDWORD lpdwError
    * LPSTR lpszBuffer
    * LPDWORD lpdwBufferLength


InternetGetLastResponseInfoW
============================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPDWORD lpdwError
    * LPWSTR lpszBuffer
    * LPDWORD lpdwBufferLength


InternetSetCookieA
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCSTR lpszUrl
    * LPCSTR lpszCookieName
    * LPCSTR lpszCookieData


InternetSetCookieW
==================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCWSTR lpszUrl
    * LPCWSTR lpszCookieName
    * LPCWSTR lpszCookieData


ReadUrlCacheEntryStream
=======================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * HANDLE hUrlCacheStream
    * DWORD dwLocation
    * LPVOID lpBuffer
    * LPDWORD lpdwLen
    * DWORD Reserved


RetrieveUrlCacheEntryFileA
==========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCSTR lpszUrlName
    * LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo
    * LPDWORD lpcbCacheEntryInfo
    * DWORD dwReserved


RetrieveUrlCacheEntryFileW
==========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * LPCWSTR lpszUrlName
    * LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo
    * LPDWORD lpcbCacheEntryInfo
    * DWORD dwReserved


RpcCertGeneratePrincipalNameA
=============================

Signature::

    * Library: rpcrt4
    * Return value: RPC_STATUS

Parameters::

    * PCCERT_CONTEXT Context
    * DWORD Flags
    * RPC_CSTR *pBuffer


RpcCertGeneratePrincipalNameW
=============================

Signature::

    * Library: rpcrt4
    * Return value: RPC_STATUS

Parameters::

    * PCCERT_CONTEXT Context
    * DWORD Flags
    * RPC_WSTR *pBuffer


SetAddrInfoExA
==============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * PCSTR pName
    * PCSTR pServiceName
    * SOCKET_ADDRESS *pAddresses
    * DWORD dwAddressCount
    * LPBLOB lpBlob
    * DWORD dwFlags
    * DWORD dwNameSpace
    * LPGUID lpNspId
    * struct timeval *timeout
    * LPOVERLAPPED lpOverlapped
    * LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine
    * LPHANDLE lpNameHandle


SetAddrInfoExW
==============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * PCWSTR pName
    * PCWSTR pServiceName
    * SOCKET_ADDRESS *pAddresses
    * DWORD dwAddressCount
    * LPBLOB lpBlob
    * DWORD dwFlags
    * DWORD dwNameSpace
    * LPGUID lpNspId
    * struct timeval *timeout
    * LPOVERLAPPED lpOverlapped
    * LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine
    * LPHANDLE lpNameHandle


UnlockUrlCacheEntryStream
=========================

Signature::

    * Library: wininet
    * Return value: BOOL

Parameters::

    * HANDLE hUrlCacheStream
    * DWORD Reserved


WSAAccept
=========

Signature::

    * Library: ws2_32
    * Return value: SOCKET

Parameters::

    * SOCKET s
    * struct sockaddr *addr
    * LPINT addrlen
    * LPCONDITIONPROC lpfnCondition
    * DWORD_PTR dwCallbackData


WSAAddressToStringA
===================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPSOCKADDR lpsaAddress
    * DWORD dwAddressLength
    * LPWSAPROTOCOL_INFOA lpProtocolInfo
    * LPSTR lpszAddressString
    * LPDWORD lpdwAddressStringLength


WSAAddressToStringW
===================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPSOCKADDR lpsaAddress
    * DWORD dwAddressLength
    * LPWSAPROTOCOL_INFOW lpProtocolInfo
    * LPWSTR lpszAddressString
    * LPDWORD lpdwAddressStringLength


WSAAsyncGetHostByAddr
=====================

Signature::

    * Library: wsock32
    * Return value: HANDLE

Parameters::

    * HWND hWnd
    * u_int wMsg
    * const char *addr
    * int len
    * int type
    * char *buf
    * int buflen


WSAAsyncGetHostByName
=====================

Signature::

    * Library: wsock32
    * Return value: HANDLE

Parameters::

    * HWND hWnd
    * u_int wMsg
    * const char *name
    * char *buf
    * int buflen


WSAAsyncGetProtoByName
======================

Signature::

    * Library: wsock32
    * Return value: HANDLE

Parameters::

    * HWND hWnd
    * u_int wMsg
    * const char *name
    * char *buf
    * int buflen


WSAAsyncGetProtoByNumber
========================

Signature::

    * Library: wsock32
    * Return value: HANDLE

Parameters::

    * HWND hWnd
    * u_int wMsg
    * int number
    * char *buf
    * int buflen


WSAAsyncGetServByName
=====================

Signature::

    * Library: wsock32
    * Return value: HANDLE

Parameters::

    * HWND hWnd
    * u_int wMsg
    * const char *name
    * const char *proto
    * char *buf
    * int buflen


WSAAsyncGetServByPort
=====================

Signature::

    * Library: wsock32
    * Return value: HANDLE

Parameters::

    * HWND hWnd
    * u_int wMsg
    * int port
    * const char *proto
    * char *buf
    * int buflen


WSAAsyncSelect
==============

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s
    * HWND hWnd
    * u_int wMsg
    * long lEvent


WSACancelAsyncRequest
=====================

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * HANDLE hAsyncTaskHandle


WSACloseEvent
=============

Signature::

    * Library: ws2_32
    * Return value: BOOL

Parameters::

    * WSAEVENT hEvent


WSAConnect
==========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * const struct sockaddr *name
    * int namelen
    * LPWSABUF lpCallerData
    * LPWSABUF lpCalleeData
    * LPQOS lpSQOS
    * LPQOS lpGQOS


WSADuplicateSocketA
===================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * DWORD dwProcessId
    * LPWSAPROTOCOL_INFOA lpProtocolInfo


WSADuplicateSocketW
===================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * DWORD dwProcessId
    * LPWSAPROTOCOL_INFOW lpProtocolInfo


WSAEnumNameSpaceProvidersA
==========================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPDWORD lpdwBufferLength
    * LPWSANAMESPACE_INFOA lpnspBuffer


WSAEnumNameSpaceProvidersW
==========================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPDWORD lpdwBufferLength
    * LPWSANAMESPACE_INFOW lpnspBuffer


WSAEnumNameSpaceProvidersExA
============================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPDWORD lpdwBufferLength
    * LPWSANAMESPACE_INFOEXA lpnspBuffer


WSAEnumNameSpaceProvidersExW
============================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPDWORD lpdwBufferLength
    * LPWSANAMESPACE_INFOEXW lpnspBuffer


WSAEnumNetworkEvents
====================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * WSAEVENT hEventObject
    * LPWSANETWORKEVENTS lpNetworkEvents


WSAEnumProtocolsA
=================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * LPINT lpiProtocols
    * LPWSAPROTOCOL_INFOA lpProtocolBuffer
    * LPDWORD lpdwBufferLength


WSAEnumProtocolsW
=================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * LPINT lpiProtocols
    * LPWSAPROTOCOL_INFOW lpProtocolBuffer
    * LPDWORD lpdwBufferLength


WSAEventSelect
==============

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * WSAEVENT hEventObject
    * long lNetworkEvents


WSAGetOverlappedResult
======================

Signature::

    * Library: ws2_32
    * Return value: BOOL

Parameters::

    * SOCKET s
    * LPWSAOVERLAPPED lpOverlapped
    * LPDWORD lpcbTransfer
    * BOOL fWait
    * LPDWORD lpdwFlags


WSAGetQOSByName
===============

Signature::

    * Library: ws2_32
    * Return value: BOOL

Parameters::

    * SOCKET s
    * LPWSABUF lpQOSName
    * LPQOS lpQOS


WSAGetServiceClassInfoA
=======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPGUID lpProviderId
    * LPGUID lpServiceClassId
    * LPDWORD lpdwBufSize
    * LPWSASERVICECLASSINFOA lpServiceClassInfo


WSAGetServiceClassInfoW
=======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPGUID lpProviderId
    * LPGUID lpServiceClassId
    * LPDWORD lpdwBufSize
    * LPWSASERVICECLASSINFOW lpServiceClassInfo


WSAGetServiceClassNameByClassIdA
================================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPGUID lpServiceClassId
    * LPSTR lpszServiceClassName
    * LPDWORD lpdwBufferLength


WSAGetServiceClassNameByClassIdW
================================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPGUID lpServiceClassId
    * LPWSTR lpszServiceClassName
    * LPDWORD lpdwBufferLength


WSAHtonl
========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * u_long hostlong
    * u_long *lpnetlong


WSAHtons
========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * u_short hostshort
    * u_short *lpnetshort


WSAInstallServiceClassA
=======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPWSASERVICECLASSINFOA lpServiceClassInfo


WSAInstallServiceClassW
=======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPWSASERVICECLASSINFOW lpServiceClassInfo


WSAIoctl
========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * DWORD dwIoControlCode
    * LPVOID lpvInBuffer
    * DWORD cbInBuffer
    * LPVOID lpvOutBuffer
    * DWORD cbOutBuffer
    * LPDWORD lpcbBytesReturned
    * LPWSAOVERLAPPED lpOverlapped
    * LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


WSAJoinLeaf
===========

Signature::

    * Library: ws2_32
    * Return value: SOCKET

Parameters::

    * SOCKET s
    * const struct sockaddr *name
    * int namelen
    * LPWSABUF lpCallerData
    * LPWSABUF lpCalleeData
    * LPQOS lpSQOS
    * LPQOS lpGQOS
    * DWORD dwFlags


WSALookupServiceBeginA
======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPWSAQUERYSETA lpqsRestrictions
    * DWORD dwControlFlags
    * LPHANDLE lphLookup


WSALookupServiceBeginW
======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPWSAQUERYSETW lpqsRestrictions
    * DWORD dwControlFlags
    * LPHANDLE lphLookup


WSALookupServiceEnd
===================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * HANDLE hLookup


WSALookupServiceNextA
=====================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * HANDLE hLookup
    * DWORD dwControlFlags
    * LPDWORD lpdwBufferLength
    * LPWSAQUERYSETA lpqsResults


WSALookupServiceNextW
=====================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * HANDLE hLookup
    * DWORD dwControlFlags
    * LPDWORD lpdwBufferLength
    * LPWSAQUERYSETW lpqsResults


WSANSPIoctl
===========

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * HANDLE hLookup
    * DWORD dwControlCode
    * LPVOID lpvInBuffer
    * DWORD cbInBuffer
    * LPVOID lpvOutBuffer
    * DWORD cbOutBuffer
    * LPDWORD lpcbBytesReturned
    * LPWSACOMPLETION lpCompletion


WSANtohl
========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * u_long netlong
    * u_long *lphostlong


WSANtohs
========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * u_short netshort
    * u_short *lphostshort


WSAPoll
=======

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * LPWSAPOLLFD fdArray
    * ULONG fds
    * INT timeout


WSAProviderConfigChange
=======================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPHANDLE lpNotificationHandle
    * LPWSAOVERLAPPED lpOverlapped
    * LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


WSARecv
=======

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * LPWSABUF lpBuffers
    * DWORD dwBufferCount
    * LPDWORD lpNumberOfBytesRecvd
    * LPDWORD lpFlags
    * LPWSAOVERLAPPED lpOverlapped
    * LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


WSARecvDisconnect
=================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * LPWSABUF lpInboundDisconnectData


WSARecvFrom
===========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * LPWSABUF lpBuffers
    * DWORD dwBufferCount
    * LPDWORD lpNumberOfBytesRecvd
    * LPDWORD lpFlags
    * struct sockaddr *lpFrom
    * LPINT lpFromlen
    * LPWSAOVERLAPPED lpOverlapped
    * LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


WSARemoveServiceClass
=====================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPGUID lpServiceClassId


WSAResetEvent
=============

Signature::

    * Library: ws2_32
    * Return value: BOOL

Parameters::

    * WSAEVENT hEvent


WSASend
=======

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * LPWSABUF lpBuffers
    * DWORD dwBufferCount
    * LPDWORD lpNumberOfBytesSent
    * DWORD dwFlags
    * LPWSAOVERLAPPED lpOverlapped
    * LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


WSASendDisconnect
=================

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * LPWSABUF lpOutboundDisconnectData


WSASendTo
=========

Signature::

    * Library: ws2_32
    * Return value: int

Parameters::

    * SOCKET s
    * LPWSABUF lpBuffers
    * DWORD dwBufferCount
    * LPDWORD lpNumberOfBytesSent
    * DWORD dwFlags
    * const struct sockaddr *lpTo
    * int iTolen
    * LPWSAOVERLAPPED lpOverlapped
    * LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine


WSASetEvent
===========

Signature::

    * Library: ws2_32
    * Return value: BOOL

Parameters::

    * WSAEVENT hEvent


WSASetLastError
===============

Signature::

    * Library: wsock32
    * Return value: void

Parameters::

    * int iError


WSASetServiceA
==============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPWSAQUERYSETA lpqsRegInfo
    * WSAESETSERVICEOP essoperation
    * DWORD dwControlFlags


WSASetServiceW
==============

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPWSAQUERYSETW lpqsRegInfo
    * WSAESETSERVICEOP essoperation
    * DWORD dwControlFlags


WSASocketA
==========

Signature::

    * Library: ws2_32
    * Return value: SOCKET

Parameters::

    * int af
    * int type
    * int protocol
    * LPWSAPROTOCOL_INFOA lpProtocolInfo
    * GROUP g
    * DWORD dwFlags


WSASocketW
==========

Signature::

    * Library: ws2_32
    * Return value: SOCKET

Parameters::

    * int af
    * int type
    * int protocol
    * LPWSAPROTOCOL_INFOW lpProtocolInfo
    * GROUP g
    * DWORD dwFlags


WSAStartup
==========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * WORD wVersionRequested
    * LPWSADATA lpWSAData


WSAStringToAddressA
===================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPSTR AddressString
    * INT AddressFamily
    * LPWSAPROTOCOL_INFOA lpProtocolInfo
    * LPSOCKADDR lpAddress
    * LPINT lpAddressLength


WSAStringToAddressW
===================

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * LPWSTR AddressString
    * INT AddressFamily
    * LPWSAPROTOCOL_INFOW lpProtocolInfo
    * LPSOCKADDR lpAddress
    * LPINT lpAddressLength


WSAWaitForMultipleEvents
========================

Signature::

    * Library: ws2_32
    * Return value: DWORD

Parameters::

    * DWORD cEvents
    * const WSAEVENT *lphEvents
    * BOOL fWaitAll
    * DWORD dwTimeout
    * BOOL fAlertable


accept
======

Signature::

    * Library: wsock32
    * Return value: SOCKET

Parameters::

    * SOCKET s
    * struct sockaddr *addr
    * int *addrlen


bind
====

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s
    * const struct sockaddr *name
    * int namelen


closesocket
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s


connect
=======

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s
    * const struct sockaddr *name
    * int namelen


freeaddrinfo
============

Signature::

    * Library: ws2_32
    * Return value: void

Parameters::

    * PADDRINFOA pAddrInfo


getaddrinfo
===========

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * PCSTR pNodeName
    * PCSTR pServiceName
    * const ADDRINFOA *pHints
    * PADDRINFOA *ppResult


gethostbyaddr
=============

Signature::

    * Library: wsock32
    * Return value: struct hostent FAR *

Parameters::

    * const char *addr
    * int len
    * int type


gethostbyname
=============

Signature::

    * Library: wsock32
    * Return value: struct hostent FAR *

Parameters::

    * const char *name


gethostname
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * char *name
    * int namelen


getnameinfo
===========

Signature::

    * Library: ws2_32
    * Return value: INT

Parameters::

    * const SOCKADDR *pSockaddr
    * socklen_t SockaddrLength
    * PCHAR pNodeBuffer
    * DWORD NodeBufferSize
    * PCHAR pServiceBuffer
    * DWORD ServiceBufferSize
    * INT Flags


getpeername
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s
    * struct sockaddr *name
    * int *namelen


getprotobyname
==============

Signature::

    * Library: wsock32
    * Return value: struct protoent FAR *

Parameters::

    * const char *name


getprotobynumber
================

Signature::

    * Library: wsock32
    * Return value: struct protoent FAR *

Parameters::

    * int number


getservbyname
=============

Signature::

    * Library: wsock32
    * Return value: struct servent FAR *

Parameters::

    * const char *name
    * const char *proto


getservbyport
=============

Signature::

    * Library: wsock32
    * Return value: struct servent FAR *

Parameters::

    * int port
    * const char *proto


getsockname
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s
    * struct sockaddr *name
    * int *namelen


getsockopt
==========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s
    * int level
    * int optname
    * char *optval
    * int *optlen


htonl
=====

Signature::

    * Library: wsock32
    * Return value: u_long

Parameters::

    * u_long hostlong


htons
=====

Signature::

    * Library: wsock32
    * Return value: u_short

Parameters::

    * u_short hostshort


inet_addr
=========

Signature::

    * Library: wsock32
    * Return value: unsigned long

Parameters::

    * const char *cp


inet_ntoa
=========

Signature::

    * Library: wsock32
    * Return value: char FAR *

Parameters::

    * struct in_addr in


ioctlsocket
===========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s
    * long cmd
    * u_long *argp


listen
======

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s
    * int backlog


ntohl
=====

Signature::

    * Library: wsock32
    * Return value: u_long

Parameters::

    * u_long netlong


ntohs
=====

Signature::

    * Library: wsock32
    * Return value: u_short

Parameters::

    * u_short netshort


recv
====

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s
    * char *buf
    * int len
    * int flags


recvfrom
========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s
    * char *buf
    * int len
    * int flags
    * struct sockaddr *from
    * int *fromlen


select
======

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * int nfds
    * fd_set *readfds
    * fd_set *writefds
    * fd_set *exceptfds
    * const struct timeval *timeout


send
====

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s
    * const char *buf
    * int len
    * int flags


sendto
======

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s
    * const char *buf
    * int len
    * int flags
    * const struct sockaddr *to
    * int tolen


setsockopt
==========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s
    * int level
    * int optname
    * const char *optval
    * int optlen


shutdown
========

Signature::

    * Library: wsock32
    * Return value: int

Parameters::

    * SOCKET s
    * int how


socket
======

Signature::

    * Library: wsock32
    * Return value: SOCKET

Parameters::

    * int af
    * int type
    * int protocol


CloseHandle
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hObject


DuplicateHandle
===============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hSourceProcessHandle
    * HANDLE hSourceHandle
    * HANDLE hTargetProcessHandle
    * LPHANDLE lpTargetHandle
    * DWORD dwDesiredAccess
    * BOOL bInheritHandle
    * DWORD dwOptions


GetHandleInformation
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hObject
    * LPDWORD lpdwFlags


SetHandleInformation
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hObject
    * DWORD dwMask
    * DWORD dwFlags


GetSystemRegistryQuota
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * PDWORD pdwQuotaAllowed
    * PDWORD pdwQuotaUsed


RegCloseKey
===========

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey


RegConnectRegistryA
===================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * LPCSTR lpMachineName
    * HKEY hKey
    * PHKEY phkResult


RegConnectRegistryW
===================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * LPCWSTR lpMachineName
    * HKEY hKey
    * PHKEY phkResult


RegCopyTreeA
============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKeySrc
    * LPCSTR lpSubKey
    * HKEY hKeyDest


RegCopyTreeW
============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKeySrc
    * LPCWSTR lpSubKey
    * HKEY hKeyDest


RegCreateKeyExA
===============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpSubKey
    * DWORD Reserved
    * LPSTR lpClass
    * DWORD dwOptions
    * REGSAM samDesired
    * const LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * PHKEY phkResult
    * LPDWORD lpdwDisposition


RegCreateKeyExW
===============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpSubKey
    * DWORD Reserved
    * LPWSTR lpClass
    * DWORD dwOptions
    * REGSAM samDesired
    * const LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * PHKEY phkResult
    * LPDWORD lpdwDisposition


RegCreateKeyTransactedA
=======================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpSubKey
    * DWORD Reserved
    * LPSTR lpClass
    * DWORD dwOptions
    * REGSAM samDesired
    * const LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * PHKEY phkResult
    * LPDWORD lpdwDisposition
    * HANDLE hTransaction
    * PVOID pExtendedParemeter


RegCreateKeyTransactedW
=======================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpSubKey
    * DWORD Reserved
    * LPWSTR lpClass
    * DWORD dwOptions
    * REGSAM samDesired
    * const LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * PHKEY phkResult
    * LPDWORD lpdwDisposition
    * HANDLE hTransaction
    * PVOID pExtendedParemeter


RegDeleteKeyA
=============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpSubKey


RegDeleteKeyW
=============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpSubKey


RegDeleteKeyExA
===============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpSubKey
    * REGSAM samDesired
    * DWORD Reserved


RegDeleteKeyExW
===============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpSubKey
    * REGSAM samDesired
    * DWORD Reserved


RegDeleteKeyTransactedA
=======================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpSubKey
    * REGSAM samDesired
    * DWORD Reserved
    * HANDLE hTransaction
    * PVOID pExtendedParameter


RegDeleteKeyTransactedW
=======================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpSubKey
    * REGSAM samDesired
    * DWORD Reserved
    * HANDLE hTransaction
    * PVOID pExtendedParameter


RegDeleteKeyValueA
==================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpSubKey
    * LPCSTR lpValueName


RegDeleteKeyValueW
==================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpSubKey
    * LPCWSTR lpValueName


RegDeleteTreeA
==============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpSubKey


RegDeleteTreeW
==============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpSubKey


RegDeleteValueA
===============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpValueName


RegDeleteValueW
===============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpValueName


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

    * HKEY hBase


RegEnableReflectionKey
======================

Signature::

    * Library: advapi32
    * Return value: LONG

Parameters::

    * HKEY hBase


RegEnumKeyExA
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * DWORD dwIndex
    * LPSTR lpName
    * LPDWORD lpcchName
    * LPDWORD lpReserved
    * LPSTR lpClass
    * LPDWORD lpcchClass
    * PFILETIME lpftLastWriteTime


RegEnumKeyExW
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * DWORD dwIndex
    * LPWSTR lpName
    * LPDWORD lpcchName
    * LPDWORD lpReserved
    * LPWSTR lpClass
    * LPDWORD lpcchClass
    * PFILETIME lpftLastWriteTime


RegEnumValueA
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * DWORD dwIndex
    * LPSTR lpValueName
    * LPDWORD lpcchValueName
    * LPDWORD lpReserved
    * LPDWORD lpType
    * LPBYTE lpData
    * LPDWORD lpcbData


RegEnumValueW
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * DWORD dwIndex
    * LPWSTR lpValueName
    * LPDWORD lpcchValueName
    * LPDWORD lpReserved
    * LPDWORD lpType
    * LPBYTE lpData
    * LPDWORD lpcbData


RegFlushKey
===========

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey


RegLoadKeyA
===========

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpSubKey
    * LPCSTR lpFile


RegLoadKeyW
===========

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpSubKey
    * LPCWSTR lpFile


RegLoadMUIStringA
=================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR pszValue
    * LPSTR pszOutBuf
    * DWORD cbOutBuf
    * LPDWORD pcbData
    * DWORD Flags
    * LPCSTR pszDirectory


RegLoadMUIStringW
=================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR pszValue
    * LPWSTR pszOutBuf
    * DWORD cbOutBuf
    * LPDWORD pcbData
    * DWORD Flags
    * LPCWSTR pszDirectory


RegNotifyChangeKeyValue
=======================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * BOOL bWatchSubtree
    * DWORD dwNotifyFilter
    * HANDLE hEvent
    * BOOL fAsynchronous


RegOpenCurrentUser
==================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * REGSAM samDesired
    * PHKEY phkResult


RegOpenKeyExA
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpSubKey
    * DWORD ulOptions
    * REGSAM samDesired
    * PHKEY phkResult


RegOpenKeyExW
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpSubKey
    * DWORD ulOptions
    * REGSAM samDesired
    * PHKEY phkResult


RegOpenKeyTransactedA
=====================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpSubKey
    * DWORD ulOptions
    * REGSAM samDesired
    * PHKEY phkResult
    * HANDLE hTransaction
    * PVOID pExtendedParemeter


RegOpenKeyTransactedW
=====================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpSubKey
    * DWORD ulOptions
    * REGSAM samDesired
    * PHKEY phkResult
    * HANDLE hTransaction
    * PVOID pExtendedParemeter


RegOpenUserClassesRoot
======================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HANDLE hToken
    * DWORD dwOptions
    * REGSAM samDesired
    * PHKEY phkResult


RegOverridePredefKey
====================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * HKEY hNewHKey


RegQueryInfoKeyA
================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPSTR lpClass
    * LPDWORD lpcchClass
    * LPDWORD lpReserved
    * LPDWORD lpcSubKeys
    * LPDWORD lpcbMaxSubKeyLen
    * LPDWORD lpcbMaxClassLen
    * LPDWORD lpcValues
    * LPDWORD lpcbMaxValueNameLen
    * LPDWORD lpcbMaxValueLen
    * LPDWORD lpcbSecurityDescriptor
    * PFILETIME lpftLastWriteTime


RegQueryInfoKeyW
================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPWSTR lpClass
    * LPDWORD lpcchClass
    * LPDWORD lpReserved
    * LPDWORD lpcSubKeys
    * LPDWORD lpcbMaxSubKeyLen
    * LPDWORD lpcbMaxClassLen
    * LPDWORD lpcValues
    * LPDWORD lpcbMaxValueNameLen
    * LPDWORD lpcbMaxValueLen
    * LPDWORD lpcbSecurityDescriptor
    * PFILETIME lpftLastWriteTime


RegQueryMultipleValuesA
=======================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * PVALENTA val_list
    * DWORD num_vals
    * LPSTR lpValueBuf
    * LPDWORD ldwTotsize


RegQueryMultipleValuesW
=======================

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * PVALENTW val_list
    * DWORD num_vals
    * LPWSTR lpValueBuf
    * LPDWORD ldwTotsize


RegQueryReflectionKey
=====================

Signature::

    * Library: advapi32
    * Return value: LONG

Parameters::

    * HKEY hBase
    * BOOL *bIsReflectionDisabled


RegQueryValueExA
================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpValueName
    * LPDWORD lpReserved
    * LPDWORD lpType
    * LPBYTE lpData
    * LPDWORD lpcbData


RegQueryValueExW
================

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpValueName
    * LPDWORD lpReserved
    * LPDWORD lpType
    * LPBYTE lpData
    * LPDWORD lpcbData


RegReplaceKeyA
==============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpSubKey
    * LPCSTR lpNewFile
    * LPCSTR lpOldFile


RegReplaceKeyW
==============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpSubKey
    * LPCWSTR lpNewFile
    * LPCWSTR lpOldFile


RegRestoreKeyA
==============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpFile
    * DWORD dwFlags


RegRestoreKeyW
==============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpFile
    * DWORD dwFlags


RegSaveKeyA
===========

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpFile
    * const LPSECURITY_ATTRIBUTES lpSecurityAttributes


RegSaveKeyW
===========

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpFile
    * const LPSECURITY_ATTRIBUTES lpSecurityAttributes


RegSaveKeyExA
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpFile
    * const LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * DWORD Flags


RegSaveKeyExW
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpFile
    * const LPSECURITY_ATTRIBUTES lpSecurityAttributes
    * DWORD Flags


RegSetKeyValueA
===============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpSubKey
    * LPCSTR lpValueName
    * DWORD dwType
    * LPCVOID lpData
    * DWORD cbData


RegSetKeyValueW
===============

Signature::

    * Library: advapi32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpSubKey
    * LPCWSTR lpValueName
    * DWORD dwType
    * LPCVOID lpData
    * DWORD cbData


RegSetValueExA
==============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpValueName
    * DWORD Reserved
    * DWORD dwType
    * const BYTE *lpData
    * DWORD cbData


RegSetValueExW
==============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpValueName
    * DWORD Reserved
    * DWORD dwType
    * const BYTE *lpData
    * DWORD cbData


RegUnLoadKeyA
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCSTR lpSubKey


RegUnLoadKeyW
=============

Signature::

    * Library: kernel32
    * Return value: LSTATUS

Parameters::

    * HKEY hKey
    * LPCWSTR lpSubKey


CancelWaitableTimer
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hTimer


ChangeTimerQueueTimer
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE TimerQueue
    * HANDLE Timer
    * ULONG DueTime
    * ULONG Period


ClosePrivateNamespace
=====================

Signature::

    * Library: kernel32
    * Return value: BOOLEAN

Parameters::

    * HANDLE Handle
    * ULONG Flags


CreateEventA
============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpEventAttributes
    * BOOL bManualReset
    * BOOL bInitialState
    * LPCSTR lpName


CreateEventW
============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpEventAttributes
    * BOOL bManualReset
    * BOOL bInitialState
    * LPCWSTR lpName


CreateEventExA
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpEventAttributes
    * LPCSTR lpName
    * DWORD dwFlags
    * DWORD dwDesiredAccess


CreateEventExW
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpEventAttributes
    * LPCWSTR lpName
    * DWORD dwFlags
    * DWORD dwDesiredAccess


CreateMutexA
============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpMutexAttributes
    * BOOL bInitialOwner
    * LPCSTR lpName


CreateMutexW
============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpMutexAttributes
    * BOOL bInitialOwner
    * LPCWSTR lpName


CreateMutexExA
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpMutexAttributes
    * LPCSTR lpName
    * DWORD dwFlags
    * DWORD dwDesiredAccess


CreateMutexExW
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpMutexAttributes
    * LPCWSTR lpName
    * DWORD dwFlags
    * DWORD dwDesiredAccess


CreatePrivateNamespaceA
=======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpPrivateNamespaceAttributes
    * LPVOID lpBoundaryDescriptor
    * LPCSTR lpAliasPrefix


CreatePrivateNamespaceW
=======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpPrivateNamespaceAttributes
    * LPVOID lpBoundaryDescriptor
    * LPCWSTR lpAliasPrefix


CreateSemaphoreA
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpSemaphoreAttributes
    * LONG lInitialCount
    * LONG lMaximumCount
    * LPCSTR lpName


CreateSemaphoreW
================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpSemaphoreAttributes
    * LONG lInitialCount
    * LONG lMaximumCount
    * LPCWSTR lpName


CreateSemaphoreExA
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpSemaphoreAttributes
    * LONG lInitialCount
    * LONG lMaximumCount
    * LPCSTR lpName
    * DWORD dwFlags
    * DWORD dwDesiredAccess


CreateSemaphoreExW
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpSemaphoreAttributes
    * LONG lInitialCount
    * LONG lMaximumCount
    * LPCWSTR lpName
    * DWORD dwFlags
    * DWORD dwDesiredAccess


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

    * PHANDLE phNewTimer
    * HANDLE TimerQueue
    * WAITORTIMERCALLBACK Callback
    * PVOID Parameter
    * DWORD DueTime
    * DWORD Period
    * ULONG Flags


CreateWaitableTimerA
====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpTimerAttributes
    * BOOL bManualReset
    * LPCSTR lpTimerName


CreateWaitableTimerW
====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpTimerAttributes
    * BOOL bManualReset
    * LPCWSTR lpTimerName


CreateWaitableTimerExA
======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpTimerAttributes
    * LPCSTR lpTimerName
    * DWORD dwFlags
    * DWORD dwDesiredAccess


CreateWaitableTimerExW
======================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPSECURITY_ATTRIBUTES lpTimerAttributes
    * LPCWSTR lpTimerName
    * DWORD dwFlags
    * DWORD dwDesiredAccess


DeleteTimerQueue
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE TimerQueue


DeleteTimerQueueEx
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE TimerQueue
    * HANDLE CompletionEvent


DeleteTimerQueueTimer
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE TimerQueue
    * HANDLE Timer
    * HANDLE CompletionEvent


GetOverlappedResult
===================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LPOVERLAPPED lpOverlapped
    * LPDWORD lpNumberOfBytesTransferred
    * BOOL bWait


MsgWaitForMultipleObjects
=========================

Signature::

    * Library: user32
    * Return value: DWORD

Parameters::

    * DWORD nCount
    * const HANDLE *pHandles
    * BOOL fWaitAll
    * DWORD dwMilliseconds
    * DWORD dwWakeMask


MsgWaitForMultipleObjectsEx
===========================

Signature::

    * Library: user32
    * Return value: DWORD

Parameters::

    * DWORD nCount
    * const HANDLE *pHandles
    * DWORD dwMilliseconds
    * DWORD dwWakeMask
    * DWORD dwFlags


OpenEventA
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * DWORD dwDesiredAccess
    * BOOL bInheritHandle
    * LPCSTR lpName


OpenEventW
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * DWORD dwDesiredAccess
    * BOOL bInheritHandle
    * LPCWSTR lpName


OpenMutexA
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * DWORD dwDesiredAccess
    * BOOL bInheritHandle
    * LPCSTR lpName


OpenMutexW
==========

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * DWORD dwDesiredAccess
    * BOOL bInheritHandle
    * LPCWSTR lpName


OpenPrivateNamespaceA
=====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPVOID lpBoundaryDescriptor
    * LPCSTR lpAliasPrefix


OpenPrivateNamespaceW
=====================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * LPVOID lpBoundaryDescriptor
    * LPCWSTR lpAliasPrefix


OpenSemaphoreA
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * DWORD dwDesiredAccess
    * BOOL bInheritHandle
    * LPCSTR lpName


OpenSemaphoreW
==============

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * DWORD dwDesiredAccess
    * BOOL bInheritHandle
    * LPCWSTR lpName


OpenWaitableTimerA
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * DWORD dwDesiredAccess
    * BOOL bInheritHandle
    * LPCSTR lpTimerName


OpenWaitableTimerW
==================

Signature::

    * Library: kernel32
    * Return value: HANDLE

Parameters::

    * DWORD dwDesiredAccess
    * BOOL bInheritHandle
    * LPCWSTR lpTimerName


PulseEvent
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hEvent


QueueUserAPC
============

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * PAPCFUNC pfnAPC
    * HANDLE hThread
    * ULONG_PTR dwData


RegisterWaitForSingleObject
===========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * PHANDLE phNewWaitObject
    * HANDLE hObject
    * WAITORTIMERCALLBACK Callback
    * PVOID Context
    * ULONG dwMilliseconds
    * ULONG dwFlags


ReleaseMutex
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hMutex


ReleaseSemaphore
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hSemaphore
    * LONG lReleaseCount
    * LPLONG lpPreviousCount


ResetEvent
==========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hEvent


SetEvent
========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hEvent


SetWaitableTimer
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hTimer
    * const LARGE_INTEGER *lpDueTime
    * LONG lPeriod
    * PTIMERAPCROUTINE pfnCompletionRoutine
    * LPVOID lpArgToCompletionRoutine
    * BOOL fResume


SetWaitableTimerEx
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hTimer
    * const LARGE_INTEGER *lpDueTime
    * LONG lPeriod
    * PTIMERAPCROUTINE pfnCompletionRoutine
    * LPVOID lpArgToCompletionRoutine
    * PREASON_CONTEXT WakeContext
    * ULONG TolerableDelay


SignalObjectAndWait
===================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * HANDLE hObjectToSignal
    * HANDLE hObjectToWaitOn
    * DWORD dwMilliseconds
    * BOOL bAlertable


SleepConditionVariableCS
========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * PCONDITION_VARIABLE ConditionVariable
    * PCRITICAL_SECTION CriticalSection
    * DWORD dwMilliseconds


SleepConditionVariableSRW
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * PCONDITION_VARIABLE ConditionVariable
    * PSRWLOCK SRWLock
    * DWORD dwMilliseconds
    * ULONG Flags


UnregisterWait
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE WaitHandle


UnregisterWaitEx
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE WaitHandle
    * HANDLE CompletionEvent


WaitForMultipleObjects
======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * DWORD nCount
    * const HANDLE *lpHandles
    * BOOL bWaitAll
    * DWORD dwMilliseconds


WaitForMultipleObjectsEx
========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * DWORD nCount
    * const HANDLE *lpHandles
    * BOOL bWaitAll
    * DWORD dwMilliseconds
    * BOOL bAlertable


WaitForSingleObject
===================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * HANDLE hHandle
    * DWORD dwMilliseconds


WaitForSingleObjectEx
=====================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * HANDLE hHandle
    * DWORD dwMilliseconds
    * BOOL bAlertable


WakeAllConditionVariable
========================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    * PCONDITION_VARIABLE ConditionVariable


WakeConditionVariable
=====================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    * PCONDITION_VARIABLE ConditionVariable


DnsHostnameToComputerNameA
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR Hostname
    * LPSTR ComputerName
    * LPDWORD nSize


DnsHostnameToComputerNameW
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR Hostname
    * LPWSTR ComputerName
    * LPDWORD nSize


EnumSystemFirmwareTables
========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    * DWORD FirmwareTableProviderSignature
    * PVOID pFirmwareTableEnumBuffer
    * DWORD BufferSize


ExpandEnvironmentStringsA
=========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCSTR lpSrc
    * LPSTR lpDst
    * DWORD nSize


ExpandEnvironmentStringsW
=========================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpSrc
    * LPWSTR lpDst
    * DWORD nSize


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

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPWSTR lpBuffer
    * LPDWORD nSize


GetComputerNameExA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * COMPUTER_NAME_FORMAT NameType
    * LPSTR lpBuffer
    * LPDWORD nSize


GetComputerNameExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * COMPUTER_NAME_FORMAT NameType
    * LPWSTR lpBuffer
    * LPDWORD nSize


GetCurrentHwProfileA
====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPHW_PROFILE_INFOA lpHwProfileInfo


GetCurrentHwProfileW
====================

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPHW_PROFILE_INFOW lpHwProfileInfo


GetFirmwareEnvironmentVariableA
===============================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCSTR lpName
    * LPCSTR lpGuid
    * PVOID pBuffer
    * DWORD nSize


GetFirmwareEnvironmentVariableW
===============================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPCWSTR lpName
    * LPCWSTR lpGuid
    * PVOID pBuffer
    * DWORD nSize


GetNativeSystemInfo
===================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    * LPSYSTEM_INFO lpSystemInfo


GetProductInfo
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * DWORD dwOSMajorVersion
    * DWORD dwOSMinorVersion
    * DWORD dwSpMajorVersion
    * DWORD dwSpMinorVersion
    * PDWORD pdwReturnedProductType


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


GetSystemFirmwareTable
======================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    * DWORD FirmwareTableProviderSignature
    * DWORD FirmwareTableID
    * PVOID pFirmwareTableBuffer
    * DWORD BufferSize


GetSystemInfo
=============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    * LPSYSTEM_INFO lpSystemInfo


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


GetSystemWow64DirectoryA
========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    * LPSTR lpBuffer
    * UINT uSize


GetSystemWow64DirectoryW
========================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    * LPWSTR lpBuffer
    * UINT uSize


GetUserNameA
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPSTR lpBuffer
    * LPDWORD pcbBuffer


GetUserNameW
============

Signature::

    * Library: advapi32
    * Return value: BOOL

Parameters::

    * LPWSTR lpBuffer
    * LPDWORD pcbBuffer


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

    * LPOSVERSIONINFOA lpVersionInformation


GetVersionExW
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPOSVERSIONINFOW lpVersionInformation


GetWindowsDirectoryA
====================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    * LPSTR lpBuffer
    * UINT uSize


GetWindowsDirectoryW
====================

Signature::

    * Library: kernel32
    * Return value: UINT

Parameters::

    * LPWSTR lpBuffer
    * UINT uSize


IsProcessorFeaturePresent
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * DWORD ProcessorFeature


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

    * HANDLE hProcess
    * PBOOL Wow64Process


QueryPerformanceCounter
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LARGE_INTEGER *lpPerformanceCount


QueryPerformanceFrequency
=========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LARGE_INTEGER *lpFrequency


SetComputerNameA
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpComputerName


SetComputerNameW
================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpComputerName


SetComputerNameExA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * COMPUTER_NAME_FORMAT NameType
    * LPCSTR lpBuffer


SetComputerNameExW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * COMPUTER_NAME_FORMAT NameType
    * LPCWSTR lpBuffer


SetFirmwareEnvironmentVariableA
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCSTR lpName
    * LPCSTR lpGuid
    * PVOID pValue
    * DWORD nSize


SetFirmwareEnvironmentVariableW
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPCWSTR lpName
    * LPCWSTR lpGuid
    * PVOID pValue
    * DWORD nSize


VerSetConditionMask
===================

Signature::

    * Library: ntdll
    * Return value: ULONGLONG

Parameters::

    * ULONGLONG ConditionMask
    * ULONG TypeMask
    * UCHAR Condition


VerifyVersionInfoA
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPOSVERSIONINFOEXA lpVersionInformation
    * DWORD dwTypeMask
    * DWORDLONG dwlConditionMask


VerifyVersionInfoW
==================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * LPOSVERSIONINFOEXW lpVersionInformation
    * DWORD dwTypeMask
    * DWORDLONG dwlConditionMask


CompareFileTime
===============

Signature::

    * Library: kernel32
    * Return value: LONG

Parameters::

    * const FILETIME *lpFileTime1
    * const FILETIME *lpFileTime2


DosDateTimeToFileTime
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * WORD wFatDate
    * WORD wFatTime
    * LPFILETIME lpFileTime


FileTimeToDosDateTime
=====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * const FILETIME *lpFileTime
    * LPWORD lpFatDate
    * LPWORD lpFatTime


FileTimeToLocalFileTime
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * const FILETIME *lpFileTime
    * LPFILETIME lpLocalFileTime


FileTimeToSystemTime
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * const FILETIME *lpFileTime
    * LPSYSTEMTIME lpSystemTime


GetDynamicTimeZoneInformation
=============================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * PDYNAMIC_TIME_ZONE_INFORMATION pTimeZoneInformation


GetFileTime
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * LPFILETIME lpCreationTime
    * LPFILETIME lpLastAccessTime
    * LPFILETIME lpLastWriteTime


GetLocalTime
============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    * LPSYSTEMTIME lpSystemTime


GetSystemTime
=============

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    * LPSYSTEMTIME lpSystemTime


GetSystemTimeAdjustment
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * PDWORD lpTimeAdjustment
    * PDWORD lpTimeIncrement
    * PBOOL lpTimeAdjustmentDisabled


GetSystemTimeAsFileTime
=======================

Signature::

    * Library: kernel32
    * Return value: void

Parameters::

    * LPFILETIME lpSystemTimeAsFileTime


GetSystemTimes
==============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * PFILETIME lpIdleTime
    * PFILETIME lpKernelTime
    * PFILETIME lpUserTime


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


GetTimeFormatA
==============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    * LCID Locale
    * DWORD dwFlags
    * const SYSTEMTIME *lpTime
    * LPCSTR lpFormat
    * LPSTR lpTimeStr
    * int cchTime


GetTimeFormatW
==============

Signature::

    * Library: kernel32
    * Return value: int

Parameters::

    * LCID Locale
    * DWORD dwFlags
    * const SYSTEMTIME *lpTime
    * LPCWSTR lpFormat
    * LPWSTR lpTimeStr
    * int cchTime


GetTimeZoneInformation
======================

Signature::

    * Library: kernel32
    * Return value: DWORD

Parameters::

    * LPTIME_ZONE_INFORMATION lpTimeZoneInformation


GetTimeZoneInformationForYear
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * USHORT wYear
    * PDYNAMIC_TIME_ZONE_INFORMATION pdtzi
    * LPTIME_ZONE_INFORMATION ptzi


LocalFileTimeToFileTime
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * const FILETIME *lpLocalFileTime
    * LPFILETIME lpFileTime


QueryUnbiasedInterruptTime
==========================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * PULONGLONG UnbiasedTime


SetDynamicTimeZoneInformation
=============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * const DYNAMIC_TIME_ZONE_INFORMATION *lpTimeZoneInformation


SetFileTime
===========

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * HANDLE hFile
    * const FILETIME *lpCreationTime
    * const FILETIME *lpLastAccessTime
    * const FILETIME *lpLastWriteTime


SetLocalTime
============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * const SYSTEMTIME *lpSystemTime


SetSystemTime
=============

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * const SYSTEMTIME *lpSystemTime


SetSystemTimeAdjustment
=======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * DWORD dwTimeAdjustment
    * BOOL bTimeAdjustmentDisabled


SetTimeZoneInformation
======================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * const TIME_ZONE_INFORMATION *lpTimeZoneInformation


SystemTimeToFileTime
====================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * const SYSTEMTIME *lpSystemTime
    * LPFILETIME lpFileTime


SystemTimeToTzSpecificLocalTime
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * const TIME_ZONE_INFORMATION *lpTimeZoneInformation
    * const SYSTEMTIME *lpUniversalTime
    * LPSYSTEMTIME lpLocalTime


SystemTimeToTzSpecificLocalTimeEx
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * const DYNAMIC_TIME_ZONE_INFORMATION *lpTimeZoneInformation
    * const SYSTEMTIME *lpUniversalTime
    * LPSYSTEMTIME lpLocalTime


TzSpecificLocalTimeToSystemTime
===============================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * const TIME_ZONE_INFORMATION *lpTimeZoneInformation
    * const SYSTEMTIME *lpLocalTime
    * LPSYSTEMTIME lpUniversalTime


TzSpecificLocalTimeToSystemTimeEx
=================================

Signature::

    * Library: kernel32
    * Return value: BOOL

Parameters::

    * const DYNAMIC_TIME_ZONE_INFORMATION *lpTimeZoneInformation
    * const SYSTEMTIME *lpLocalTime
    * LPSYSTEMTIME lpUniversalTime


