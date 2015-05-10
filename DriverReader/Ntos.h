#ifndef _NTOS_H_
#define _NTOS_H_
#include "struct.h"
#include "KernelReload.h"
#include "Win32k.h"
//

BYTE* ReloadNtosImageBase;
ULONG SystemKernelModuleBase;
ULONG SystemKernelModuleSize;
WCHAR *SystemKernelFilePath;

ULONG g_RealReadMemoryAddress;
ULONG g_RealWriteMemoryAddress;
ULONG g_RealOpenProcessAddress;
//
ULONG g_NtDuplicateObjectAddress;
ULONG g_NtCreateThreadAddress;
ULONG g_NtSetContextThreadAddress;
//
ULONG g_NtSuspendProcessAddress;
ULONG g_NtSuspendThreadAddress;
//
ULONG g_RealNtUserGetMessageAddress;
ULONG g_RealNtUserPeekMessageAddress;
ULONG g_RealNtGdiBitBltAddress;
ULONG g_RealNtGdiStretchBltAddress;
ULONG g_RealNtUserSetWindowsHookExAddress;
ULONG g_RealNtUserUnhookWindowsHookExAddress;
extern PDRIVER_OBJECT 	g_MyDriverObject;//自身驱动的基址

PSERVICE_DESCRIPTOR_TABLE ReloadServiceTable;
PSERVICE_DESCRIPTOR_TABLE g_pOriginShadowTable;
PSERVICE_DESCRIPTOR_TABLE ReloadShadowServiceTable;

PVOID GetShadowTableAddress();
NTSTATUS ReloadNtos(PDRIVER_OBJECT   DriverObject);




#endif