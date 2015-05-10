#pragma once
#include "struct.h"
typedef BOOLEAN( *EX_ENUMERATE_HANDLE_ROUTINE )(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN OUT PVOID EnumParameter
	);

typedef BOOLEAN( *PExEnumHandleTable )(
	IN PHANDLE_TABLE HandleTable,
	IN EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
	IN PVOID EnumParameter,
	OUT PHANDLE Handle OPTIONAL
	);

VOID HideProcessByName(PCHAR ProcessName);
VOID HideProcess(PEPROCESS eprocess);
VOID ResumeProcess();
//»Ö¸´PSPtable
VOID RecoverPspTable();
BOOL InitReplaceFunctions();
//VOID InitSvchostRecord();