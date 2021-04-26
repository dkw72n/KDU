/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.10
*
*  DATE:        02 Apr 2021
*
*  Common include header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#if !defined UNICODE
#error ANSI build is not supported
#endif

//
// Ignored warnings
//
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4091) // 'typedef ': ignored on left of '%s' when no variable is declared
#pragma warning(disable: 4201) // nameless struct/union
#pragma warning(disable: 26812) // Prefer 'enum class' over 'enum'

#define KDU_SHELLCODE_NONE  (0)
#define KDU_SHELLCODE_V1    (1)
#define KDU_SHELLCODE_V2    (2)
#define KDU_SHELLCODE_V3    (3)
#define KDU_SHELLCODE_VMAX  KDU_SHELLCODE_V3

#include <Windows.h>
#include <strsafe.h>
#include <ntstatus.h>
#include <intrin.h>
#include <rpc.h>
#include "../Shared/ntos/ntos.h"
#include "../Shared/ntos/halamd64.h"
#include "wdksup.h"
#include "resource.h"

#pragma comment(lib, "Rpcrt4.lib")

#if defined(__cplusplus)
extern "C" {
#endif

#include "hde/hde64.h"
#include "../Shared/minirtl/minirtl.h"
#include "../Shared/minirtl/rtltypes.h"
#include "../Shared/minirtl/cmdline.h"
#include "../Shared/minirtl/_filename.h"

#ifdef __cplusplus
}
#endif

#include "consts.h"
#include "sup.h"
#include "compress.h"
#include "kduprov.h"
#include "shellcode.h"
#include "drvmap.h"
#include "ps.h"
#include "victim.h"
#include "pagewalk.h"
#include "dsefix.h"
#include "tests.h"
#include "mf.h"

#define ASSERT_RESOLVED_FUNC(FunctionPtr) { if (FunctionPtr == 0) break; }
#define ASSERT_RESOLVED_FUNC_ABORT(FunctionPtr) { if (FunctionPtr == 0) return FALSE; }
