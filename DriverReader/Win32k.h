#pragma once
#include "struct.h"
#include "KernelReload.h"
#include "ldasm.h"
BYTE*  ReloadWin32kImageBase;
ULONG SystemWin32kBase;

extern PDRIVER_OBJECT 	g_MyDriverObject;//自身驱动的基址

BOOL GetOriginalW32pTable(PVOID ImageBase,
	PSERVICE_DESCRIPTOR_TABLE W32pTable,
	DWORD Win32kBase);
NTSTATUS ReloadWin32k(PDRIVER_OBJECT   DriverObject);