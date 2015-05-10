#pragma once
#include "struct.h"
#include "CommonFunc.h"
#include "ldasm.h"
#include "KernelReload.h"

#define NOTIFY_ADDRESS_CALC_ONE(x) ((x) & ~7)
#define HIGH_12BIT_OF_ULONG(x)  ((ULONG)((x)>>20))
#define HIGH_BYTE_OF_ULONG(x)  ((BYTE)((x)>>24))
extern PDRIVER_OBJECT 	g_MyDriverObject;
extern 
	NTSTATUS PsLookupThreadByThreadId(
	HANDLE ThreadId,
	PETHREAD *Thread
	);
BOOL InitNotifyRoutineAddress();
NTSTATUS SetDeleteNotifyThread();
VOID RemoveDeleteNotifyThread();
VOID RemoveNotifyRoutines();
/*VOID TestEnumNotifyRoutine();*/