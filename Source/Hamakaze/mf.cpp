/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       MF.CPP
*
*  VERSION:     0.01
*
*  DATE:        13 Apr 2021
*
*  Processes DKOM related routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

LPSTR KDUGetProtectionTypeAsString2(
    _In_ ULONG Type
)
{
    LPSTR pStr;

    switch (Type) {

    case PsProtectedTypeNone:
        pStr = (LPSTR)"PsProtectedTypeNone";
        break;
    case PsProtectedTypeProtectedLight:
        pStr = (LPSTR)"PsProtectedTypeProtectedLight";
        break;
    case PsProtectedTypeProtected:
        pStr = (LPSTR)"PsProtectedTypeProtected";
        break;
    default:
        pStr = (LPSTR)"Unknown Type";
        break;
    }

    return pStr;
}

LPSTR KDUGetProtectionSignerAsString2(
    _In_ ULONG Signer
)
{
    LPSTR pStr;

    switch (Signer) {
    case PsProtectedSignerNone:
        pStr = (LPSTR)"PsProtectedSignerNone";
        break;
    case PsProtectedSignerAuthenticode:
        pStr = (LPSTR)"PsProtectedSignerAuthenticode";
        break;
    case PsProtectedSignerCodeGen:
        pStr = (LPSTR)"PsProtectedSignerCodeGen";
        break;
    case PsProtectedSignerAntimalware:
        pStr = (LPSTR)"PsProtectedSignerAntimalware";
        break;
    case PsProtectedSignerLsa:
        pStr = (LPSTR)"PsProtectedSignerLsa";
        break;
    case PsProtectedSignerWindows:
        pStr = (LPSTR)"PsProtectedSignerWindows";
        break;
    case PsProtectedSignerWinTcb:
        pStr = (LPSTR)"PsProtectedSignerWinTcb";
        break;
    case PsProtectedSignerWinSystem:
        pStr = (LPSTR)"PsProtectedSignerWinSystem";
        break;
    case PsProtectedSignerApp:
        pStr = (LPSTR)"PsProtectedSignerApp";
        break;
    default:
        pStr = (LPSTR)"Unknown Value";
        break;
    }

    return pStr;
}

struct SignatureLevelOpts {
    UCHAR SignatureLevel;
    UCHAR SectionSignatureLevel;
    // UCHAR dummy[6];
};

const char* MitigationFlagsNames[64] = {
    "ControlFlowGuardEnabled",
    "ControlFlowGuardExportSuppressionEnabled",
    "ControlFlowGuardStrict",
    "DisallowStrippedImages",
    "ForceRelocateImages",
    "HighEntropyASLREnabled",
    "StackRandomizationDisabled",
    "ExtensionPointDisable",
    "DisableDynamicCode",
    "DisableDynamicCodeAllowOptOut",
    "DisableDynamicCodeAllowRemoteDowngrade",
    "AuditDisableDynamicCode",
    "DisallowWin32kSystemCalls",
    "AuditDisallowWin32kSystemCalls",
    "EnableFilteredWin32kAPIs",
    "AuditFilteredWin32kAPIs",
    "DisableNonSystemFonts",
    "AuditNonSystemFontLoading",
    "PreferSystem32Images",
    "ProhibitRemoteImageMap",
    "AuditProhibitRemoteImageMap",
    "ProhibitLowILImageMap",
    "AuditProhibitLowILImageMap",
    "SignatureMitigationOptIn",
    "AuditBlockNonMicrosoftBinaries",
    "AuditBlockNonMicrosoftBinariesAllowStore",
    "LoaderIntegrityContinuityEnabled",
    "AuditLoaderIntegrityContinuity",
    "EnableModuleTamperingProtection",
    "EnableModuleTamperingProtectionNoInherit",
    "RestrictIndirectBranchPrediction",
    "IsolateSecurityDomain",
    "EnableExportAddressFilter",
    "AuditExportAddressFilter",
    "EnableExportAddressFilterPlus",
    "AuditExportAddressFilterPlus",
    "EnableRopStackPivot",
    "AuditRopStackPivot",
    "EnableRopCallerCheck",
    "AuditRopCallerCheck",
    "EnableRopSimExec",
    "AuditRopSimExec",
    "EnableImportAddressFilter",
    "AuditImportAddressFilter",
    "DisablePageCombine",
    "SpeculativeStoreBypassDisable",
    "CetUserShadowStacks",
    "AuditCetUserShadowStacks",
    "AuditCetUserShadowStacksLogged",
    "UserCetSetContextIpValidation",
    "AuditUserCetSetContextIpValidation",
    "AuditUserCetSetContextIpValidationLogged",
    "CetUserShadowStacksStrictMode",
    "BlockNonCetBinaries",
    "BlockNonCetBinariesNonEhcont",
    "AuditBlockNonCetBinaries",
    "AuditBlockNonCetBinariesLogged",
    "XtendedControlFlowGuard",
    "AuditXtendedControlFlowGuard",
    "PointerAuthUserIp",
    "AuditPointerAuthUserIp",
    "AuditPointerAuthUserIpLogged",
    "CetDynamicApisOutOfProcOnly",
    "UserCetSetContextIpValidationRelaxedMode",
}; // from https://github.com/yardenshafir/MitigationFlagsCliTool/blob/master/MitigationFlagsCliTool/Main.cpp

struct MitigationFlagsCombine {
    union
    {
        UINT32 MitigationFlags;
        struct // _TAG_UNNAMED_88
        {
            struct /* bitfield */
            {
                UINT32 ControlFlowGuardEnabled : 1; /* bit position: 0 */
                UINT32 ControlFlowGuardExportSuppressionEnabled : 1; /* bit position: 1 */
                UINT32 ControlFlowGuardStrict : 1; /* bit position: 2 */
                UINT32 DisallowStrippedImages : 1; /* bit position: 3 */
                UINT32 ForceRelocateImages : 1; /* bit position: 4 */
                UINT32 HighEntropyASLREnabled : 1; /* bit position: 5 */
                UINT32 StackRandomizationDisabled : 1; /* bit position: 6 */
                UINT32 ExtensionPointDisable : 1; /* bit position: 7 */
                UINT32 DisableDynamicCode : 1; /* bit position: 8 */
                UINT32 DisableDynamicCodeAllowOptOut : 1; /* bit position: 9 */
                UINT32 DisableDynamicCodeAllowRemoteDowngrade : 1; /* bit position: 10 */
                UINT32 AuditDisableDynamicCode : 1; /* bit position: 11 */
                UINT32 DisallowWin32kSystemCalls : 1; /* bit position: 12 */
                UINT32 AuditDisallowWin32kSystemCalls : 1; /* bit position: 13 */
                UINT32 EnableFilteredWin32kAPIs : 1; /* bit position: 14 */
                UINT32 AuditFilteredWin32kAPIs : 1; /* bit position: 15 */
                UINT32 DisableNonSystemFonts : 1; /* bit position: 16 */
                UINT32 AuditNonSystemFontLoading : 1; /* bit position: 17 */
                UINT32 PreferSystem32Images : 1; /* bit position: 18 */
                UINT32 ProhibitRemoteImageMap : 1; /* bit position: 19 */
                UINT32 AuditProhibitRemoteImageMap : 1; /* bit position: 20 */
                UINT32 ProhibitLowILImageMap : 1; /* bit position: 21 */
                UINT32 AuditProhibitLowILImageMap : 1; /* bit position: 22 */
                UINT32 SignatureMitigationOptIn : 1; /* bit position: 23 */
                UINT32 AuditBlockNonMicrosoftBinaries : 1; /* bit position: 24 */
                UINT32 AuditBlockNonMicrosoftBinariesAllowStore : 1; /* bit position: 25 */
                UINT32 LoaderIntegrityContinuityEnabled : 1; /* bit position: 26 */
                UINT32 AuditLoaderIntegrityContinuity : 1; /* bit position: 27 */
                UINT32 EnableModuleTamperingProtection : 1; /* bit position: 28 */
                UINT32 EnableModuleTamperingProtectionNoInherit : 1; /* bit position: 29 */
                UINT32 RestrictIndirectBranchPrediction : 1; /* bit position: 30 */
                UINT32 IsolateSecurityDomain : 1; /* bit position: 30 */
            }; /* bitfield */
        } /* size: 0x0004 */ MitigationFlagsValues;
    }; /* size: 0x0004 */
    union
    {
        UINT32 MitigationFlags2;
        struct // _TAG_UNNAMED_89
        {
            struct /* bitfield */
            {
                UINT32 EnableExportAddressFilter : 1; /* bit position: 0 */
                UINT32 AuditExportAddressFilter : 1; /* bit position: 1 */
                UINT32 EnableExportAddressFilterPlus : 1; /* bit position: 2 */
                UINT32 AuditExportAddressFilterPlus : 1; /* bit position: 3 */
                UINT32 EnableRopStackPivot : 1; /* bit position: 4 */
                UINT32 AuditRopStackPivot : 1; /* bit position: 5 */
                UINT32 EnableRopCallerCheck : 1; /* bit position: 6 */
                UINT32 AuditRopCallerCheck : 1; /* bit position: 7 */
                UINT32 EnableRopSimExec : 1; /* bit position: 8 */
                UINT32 AuditRopSimExec : 1; /* bit position: 9 */
                UINT32 EnableImportAddressFilter : 1; /* bit position: 10 */
                UINT32 AuditImportAddressFilter : 1; /* bit position: 11 */
                UINT32 DisablePageCombine : 1; /* bit position: 12 */
                UINT32 MemoryDisambiguationDisable : 1; /* bit position: 13 */
            }; /* bitfield */
        } /* size: 0x0004 */ MitigationFlags2Values;
    }; /* size: 0x0004 */
};

/*
* KDUControlProcess
*
* Purpose:
*
* Modify process object to remove MitigationFlags.
*
*/
BOOL KDURemoveProcessMFs(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG_PTR ProcessId)
{
    BOOL       bResult = FALSE;
    ULONG      Buffer;
    MitigationFlagsCombine Flags;
    SignatureLevelOpts SigOpts;
    NTSTATUS   ntStatus;
    ULONG_PTR  ProcessObject = 0, VirtualAddressMF = 0, VirtualAddressSO = 0, OffsetMF = 0, OffsetSO = 0;
    HANDLE     hProcess = NULL;

    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES obja;

    PS_PROTECTION* PsProtection;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    InitializeObjectAttributes(&obja, NULL, 0, 0, 0);

    clientId.UniqueProcess = (HANDLE)ProcessId;
    clientId.UniqueThread = NULL;

    ntStatus = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        &obja, &clientId);

    if (NT_SUCCESS(ntStatus)) {

        printf_s("[+] Process with PID %llu opened (PROCESS_QUERY_LIMITED_INFORMATION)\r\n", ProcessId);
        supQueryObjectFromHandle(hProcess, &ProcessObject);

        if (ProcessObject != 0) {

            printf_s("[+] Process object (EPROCESS) found, 0x%llX\r\n", ProcessObject);

            switch (Context->NtBuildNumber) {
#if 0
            case NT_WIN8_BLUE:
                Offset = PsProtectionOffset_9600;
                break;
            case NT_WIN10_THRESHOLD1:
                Offset = PsProtectionOffset_10240;
                break;
            case NT_WIN10_THRESHOLD2:
                Offset = PsProtectionOffset_10586;
                break;
            case NT_WIN10_REDSTONE1:
                Offset = PsProtectionOffset_14393;
                break;
            case NT_WIN10_REDSTONE2:
            case NT_WIN10_REDSTONE3:
            case NT_WIN10_REDSTONE4:
            case NT_WIN10_REDSTONE5:
            case NT_WIN10_19H1:
            case NT_WIN10_19H2:
                Offset = PsProtectionOffset_15063;
                break;
#endif
            case NT_WIN10_20H1:
            case NT_WIN10_20H2:
            case NT_WIN10_21H1:
            case NTX_WIN10_ADB:
                OffsetMF = MitigationFlagOffset_19041;
                OffsetSO = SignatureLevelOffset_19041;
                break;
            default:
                OffsetMF = 0;
                OffsetSO == 0;
                break;
            }

            if (OffsetMF == 0 || OffsetSO == 0) {
                printf_s("[!] Unsupported WinNT version: %d\r\n", Context->NtBuildNumber);
            }
            else {

                VirtualAddressMF = EPROCESS_TO_PROTECTION(ProcessObject, OffsetMF);
                VirtualAddressSO = EPROCESS_TO_PROTECTION(ProcessObject, OffsetSO);

                printf_s("[+] EPROCESS->MitigationFlags, 0x%llX\r\n", VirtualAddressMF);
                printf_s("[+] EPROCESS->SignatureOptions, 0x%llX\r\n", VirtualAddressSO);

                if (KDUReadKernelVM(Context, VirtualAddressMF, &Flags, sizeof(Flags)) && KDUReadKernelVM(Context, VirtualAddressSO, &SigOpts, sizeof(SigOpts))) {

                    LPSTR pStr;


                    printf_s("[+] Kernel memory read succeeded\r\n");
                    printf_s("[+] Signature Options: %d %d\r\n", SigOpts.SignatureLevel, SigOpts.SectionSignatureLevel);

                    printf_s("[+] Mitigation Flags: %08x %08x\r\n", Flags.MitigationFlags, Flags.MitigationFlags2);
                    LONG64 mitigation = Flags.MitigationFlags + ((LONG64)Flags.MitigationFlags2 << 32);
                    for (int i = 0; i < 64; ++i) {
                        if (!MitigationFlagsNames[i]) break;
                        if (_bittest64(&mitigation, i)) {
                            printf_s("[+]\t%s\r\n", MitigationFlagsNames[i]);
                        }
                    }

                    /*
                    pStr = KDUGetProtectionTypeAsString2(PsProtection->Type);
                    printf_s("\tPsProtection->Type: %lu (%s)\r\n",
                        PsProtection->Type,
                        pStr);

                    printf_s("\tPsProtection->Audit: %lu\r\n", PsProtection->Audit);

                    pStr = KDUGetProtectionSignerAsString2(PsProtection->Signer);
                    printf_s("\tPsProtection->Signer: %lu (%s)\r\n",
                        PsProtection->Signer,
                        pStr);

                    PsProtection->Signer = PsProtectedSignerNone;
                    PsProtection->Type = PsProtectedTypeNone;
                    PsProtection->Audit = 0;

                    bResult = KDUWriteKernelVM(Context, VirtualAddress, &Buffer, sizeof(ULONG));
                    if (bResult) {
                        printf_s("[+] Process object modified\r\n");

                        pStr = KDUGetProtectionTypeAsString2(PsProtection->Type);
                        printf_s("\tNew PsProtection->Type: %lu (%s)\r\n",
                            PsProtection->Type,
                            pStr);

                        pStr = KDUGetProtectionSignerAsString2(PsProtection->Signer);
                        printf_s("\tNew PsProtection->Signer: %lu (%s)\r\n",
                            PsProtection->Signer,
                            pStr);

                        printf_s("\tNew PsProtection->Audit: %lu\r\n", PsProtection->Audit);

                    }
                    else {
                        printf_s("[!] Cannot modify process object\r\n");
                    }
                    */
                }
                else {
                    printf_s("[!] Cannot read kernel memory\r\n");
                }
            }
        }
        else {
            printf_s("[!] Cannot query process object\r\n");
        }
        NtClose(hProcess);
    }
    else {
        printf_s("[!] Cannot open target process, NTSTATUS (0x%lX)\r\n", ntStatus);
    }

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return bResult;
}
