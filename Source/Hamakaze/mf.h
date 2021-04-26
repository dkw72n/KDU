/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2021
*
*  TITLE:       MF.H
*
*  VERSION:     1.02
*
*  DATE:        11 Feb 2021
*
*  Processes support prototypes and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

/*
#define PsProtectionOffset_9600  (ULONG_PTR)0x67A
#define PsProtectionOffset_10240 (ULONG_PTR)0x6AA
#define PsProtectionOffset_10586 (ULONG_PTR)0x6B2
#define PsProtectionOffset_14393 (ULONG_PTR)0x6C2
#define PsProtectionOffset_15063 (ULONG_PTR)0x6CA //same for 16299, 17134, 17763
#define PsProtectionOffset_18362 (ULONG_PTR)0x6FA
#define PsProtectionOffset_18363 (ULONG_PTR)0x6FA
*/
#define MitigationFlagOffset_19041 (ULONG_PTR)0x9d0 //same for 19042..19043

#define SignatureLevelOffset_19041 (ULONG_PTR)0x878

#define EPROCESS_TO_PROTECTION(Object, MitigationFlagOffset) ((ULONG_PTR)Object + (ULONG_PTR)MitigationFlagOffset)

BOOL KDURemoveProcessMFs(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG_PTR ProcessId);
