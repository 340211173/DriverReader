#ifndef _KERNELRELOAD_H_
#define _KERNELRELOAD_H_
#include "struct.h"
#include "CommonFunc.h"
#include "FileSystem.h"
#include "Fixrelocation.h"
char NtosModuleName[260];

BOOL GetNtosInformation(WCHAR** pKernelFullPath,
	ULONG* ulKernelBase, 
	ULONG* ulKernelSize);

PVOID GetKernelModuleBase(PDRIVER_OBJECT DriverObject,CHAR *KernelModuleName);
BOOL PeReload(WCHAR* wszFullPath,
	DWORD ulKernelBase,
	BYTE** ulReloadImageBase,
	PDRIVER_OBJECT DeviceObject);
#endif
