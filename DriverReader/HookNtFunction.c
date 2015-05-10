#include "HookNtFunction.h"
ULONG g_OriginKiFastCallEntryAddress;
ULONG g_NewKiFastCallEntryAddress;
ULONG g_HookNewKiFastCallEntryAddress;
PVOID lpHookOriginKiFastCallEntryRet;
PVOID lpHookNewKiFastCallEntryRet;
int PatchOriginKiFastCallEntryLen;
/* */
PEPROCESS ExplorerProcess;
PVOID lpUserGetMessageRet;
PVOID lpUserPeekMessageRet;
//PVOID lpGdiBitBltRet;
PVOID lpSetWindowsHookExRet;
int patchNtUserWindowsHookExLen;
//PVOID lpGdiStrechBltRet;
int patchlen1;
int patchlen2;
int patchlen3;
int patchlen4;
int patchlen5;
int patchlen6;
int patchlen7;
int patchlen8;
PVOID lpKeRet;
//////////////////////////////////////////////////////////////////////////
static ULONG s_OriginObReferenceObjectByHandle;
static PVOID s_lpOriginObReferenceObjectByHandleRet;
static int PatchObReferenceObjectByHandleLen;


//
// HANDLE GetCsrPid()
// {
// 	HANDLE Process,hObject;
// 	HANDLE CsrId = (HANDLE)0;
// 	OBJECT_ATTRIBUTES obj;
// 	CLIENT_ID cid;
// 	UCHAR Buff[0x100];
// 	POBJECT_NAME_INFORMATION ObjName = (PVOID)&Buff;
// 	PSYSTEM_HANDLE_INFORMATION_EX Handles;
// 	ULONG i;
// 	ULONG nSize;
// 
// 	//获取PSYSTEM_HANDLE_INFORMATION_EX
// 	Handles = GetInfoTable(&nSize);
// 	if(!Handles)
// 	{
// 		return CsrId;
// 	}
// 	for(i = 0; i < Handles->NumberOfHandles; i++)
// 	{
// 		if(Handles->Information[i].ObjectTypeNumber == 21)
// 		{
// 			InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
// 			cid.UniqueProcess = (HANDLE)Handles->Information[i].ProcessId;
// 			cid.UniqueThread  = 0;
// 
// 			//打开进程
// 			if(NT_SUCCESS(NtOpenProcess(&Process, PROCESS_DUP_HANDLE, &obj, &cid)))
// 			{
// 				//copy handle
// 				if(NT_SUCCESS(ZwDuplicateObject(Process, (HANDLE)Handles->Information[i].Handle, NtCurrentProcess(), &hObject, 0, 0, DUPLICATE_SAME_ACCESS)))
// 				{
// 					//query
// 					if(NT_SUCCESS(ZwQueryObject(hObject, ObjectNameInformation, ObjName, 0x100, NULL)))
// 					{
// 						if(ObjName->Name.Buffer && !wcsncmp(L"\\Windows\\ApiPort", ObjName->Name.Buffer, 20))
// 						{
// 							//返回pid
// 							CsrId = (HANDLE)Handles->Information[i].ProcessId;
// 							CodeVprint("Csrss.exe PID = %d", CsrId);
// 						}
// 					}
// 					ZwClose(hObject);
// 				}
// 				ZwClose(Process);
// 			}
// 		}
// 	}
// 	ExFreePool(Handles);
// 	return CsrId;
// }

NTSTATUS
__stdcall
	NewNtOpenProcess (
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	 PCLIENT_ID ClientId
	)
{
	NTSTATUS st;
	PEPROCESS eprocess_debugger;
	PEPROCESS eprocess_ctfmon;
	HANDLE CsrId = (HANDLE)0;
	NTOPENPROCESS SSDT_NtOpenProcess;
	SSDT_NtOpenProcess=(NTOPENPROCESS)g_RealOpenProcessAddress;
	if (IsFromGameProcess())
	{
		//CodeVprint("tp is  calling NtOpenProcess\r\n");
		if (MmIsAddressValidEx(ClientId))
		{
			if (ClientId->UniqueProcess)
			{
				if ((ULONG)(ClientId->UniqueProcess) == g_nProtectId)
				{
					/* 把我们的进程id改为csrss的id */
					CodeVprint("TP is detecting our process\r\n");
					//CsrId = GetCsrPid();
					ClientId->UniqueProcess = (HANDLE)4;
				}
			}
		}
		return SSDT_NtOpenProcess(ProcessHandle,
									DesiredAccess,
									ObjectAttributes,
									ClientId);
	}
	ReloadNtOpenProcess = (NTOPENPROCESS)(g_RealOpenProcessAddress - 
		SystemKernelModuleBase + 
		(ULONG)ReloadNtosImageBase);
	return ReloadNtOpenProcess(ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ClientId);
}

NTSTATUS
	__stdcall
	NewNtReadVirtualMemory (
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__out_bcount(BufferSize) PVOID Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesRead
	)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	if (PsGetCurrentProcess() == g_pProtectProcess)
	{
		ReloadNtReadVirtualMemory = (NTREADVIRTUALMEMORY)(g_RealReadMemoryAddress - 
			SystemKernelModuleBase + 
			(ULONG)ReloadNtosImageBase);
		//if (MmIsAddressValid(ReloadNtReadVirtualMemory))
		//{
			return ReloadNtReadVirtualMemory(ProcessHandle,
				BaseAddress,
				Buffer,
				BufferSize,
				NumberOfBytesRead);
		//}
	}else if (IsFromGameProcess())
	{
		nStatus = ObReferenceObjectByHandle(ProcessHandle,
			0,
			*PsProcessType,
			KernelMode,
			(PVOID*)&pProcess,
			NULL);
		if (!NT_SUCCESS(nStatus))
		{
			return STATUS_INVALID_PARAMETER;
		}
		ObDereferenceObject(pProcess);
		if (pProcess == g_pProtectProcess)
		{
			return STATUS_ACCESS_DENIED;
		}
	}
	return ((NTREADVIRTUALMEMORY)g_RealReadMemoryAddress)(ProcessHandle,
		BaseAddress,
		Buffer,
		BufferSize,
		NumberOfBytesRead);
}

NTSTATUS
__stdcall
	NewNtWriteVirtualMemory (
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__in_bcount(BufferSize) CONST VOID *Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesWritten
	)
{
	if (PsGetCurrentProcess() == g_pProtectProcess)
	{
		ReloadNtWriteVirtualMemory = (NTWRITEVIRTUALMEMORY)(g_RealWriteMemoryAddress - 
			SystemKernelModuleBase + 
			(ULONG)ReloadNtosImageBase);
		//if (MmIsAddressValid(ReloadNtReadVirtualMemory))
		//{
		return ReloadNtWriteVirtualMemory(ProcessHandle,
			BaseAddress,
			Buffer,
			BufferSize,
			NumberOfBytesWritten);
		//}
	}
	return ((NTWRITEVIRTUALMEMORY)g_RealWriteMemoryAddress)(ProcessHandle,
		BaseAddress,
		Buffer,
		BufferSize,
		NumberOfBytesWritten);
}
/**/
NTSTATUS
	__stdcall
	NewNtCreateThread(
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in HANDLE ProcessHandle,
	__out PCLIENT_ID ClientId,
	__in PCONTEXT ThreadContext,
	__in PVOID InitialTeb,
	__in BOOL CreateSuspended
	)
{
	if (PsGetCurrentProcess() == g_pProtectProcess)
	{
		ReloadNtCreateThread = (NTCREATETHREAD)(g_NtCreateThreadAddress - 
			SystemKernelModuleBase + 
			(ULONG)ReloadNtosImageBase);
		//if (MmIsAddressValid(ReloadNtReadVirtualMemory))
		//{
		return ReloadNtCreateThread(ThreadHandle,
			DesiredAccess,
			ObjectAttributes,
			ProcessHandle,
			ClientId,
			ThreadContext,
			InitialTeb,
			CreateSuspended);
		//}
	}
	return ((NTCREATETHREAD)g_NtCreateThreadAddress)(ThreadHandle,
		DesiredAccess,
		ObjectAttributes,
		ProcessHandle,
		ClientId,
		ThreadContext,
		InitialTeb,
		CreateSuspended);
}

NTSTATUS
__stdcall
	NewNtDuplicateObject (
	__in HANDLE SourceProcessHandle,
	__in HANDLE SourceHandle,
	__in_opt HANDLE TargetProcessHandle,
	__out_opt PHANDLE TargetHandle,
	__in ACCESS_MASK DesiredAccess,
	__in ULONG HandleAttributes,
	__in ULONG Options
	)
{
	if (PsGetCurrentProcess() == g_pProtectProcess)
	{
		ReloadNtDuplicateobject = (NTDUPLICATEOBJECT)(g_NtDuplicateObjectAddress - 
			SystemKernelModuleBase + 
			(ULONG)ReloadNtosImageBase);
		//if (MmIsAddressValid(ReloadNtReadVirtualMemory))
		//{
		return ReloadNtDuplicateobject(SourceProcessHandle,
			SourceHandle,
			TargetProcessHandle,
			TargetHandle,
			DesiredAccess,
			HandleAttributes,
			Options);
		//}
	}
	return ((NTDUPLICATEOBJECT)g_NtDuplicateObjectAddress)(SourceProcessHandle,
		SourceHandle,
		TargetProcessHandle,
		TargetHandle,
		DesiredAccess,
		HandleAttributes,
		Options);
}
//
NTSTATUS __stdcall NewNtSuspendProcess(
	__in HANDLE ProcessHandle
	)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	if (IsFromGameProcess())
	{
		nStatus = ObReferenceObjectByHandle(ProcessHandle,
			0,
			*PsProcessType,
			KernelMode,
			(PVOID*)&pProcess,
			NULL);
		if (!NT_SUCCESS(nStatus))
		{
			return STATUS_INVALID_PARAMETER;
		}
		ObDereferenceObject(pProcess);
		if (pProcess = g_pProtectProcess)
		{
			return STATUS_ACCESS_DENIED;
		}
		return ((NTSUSPENDPROCESS)g_NtSuspendProcessAddress)(ProcessHandle);
	}
	ReloadNtSuspendProcess = (NTSUSPENDPROCESS)(g_NtSuspendProcessAddress - 
		SystemKernelModuleBase + 
		(ULONG)ReloadNtosImageBase);
	//if (MmIsAddressValid(ReloadNtReadVirtualMemory))
	//{
	return ReloadNtSuspendProcess(ProcessHandle);

}
NTSTATUS __stdcall NewNtSuspendThread(
	__in HANDLE ThreadHandle,
	__out_opt PULONG PreviousSuspendCount
	)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	PETHREAD pThread = NULL;
	if (IsFromGameProcess())
	{
		nStatus = ObReferenceObjectByHandle(ThreadHandle,
			0,
			*PsThreadType,
			KernelMode,
			(PVOID*)&pThread,
			NULL);
		if (!NT_SUCCESS(nStatus))
		{
			return STATUS_INVALID_PARAMETER;
		}
		ObDereferenceObject(pThread);
		//通过线程句柄获取进程
		pProcess = IoThreadToProcess(pThread);
		if (pProcess = g_pProtectProcess)
		{
			return STATUS_ACCESS_DENIED;
		}
		return ((NTSUSPENDTHREAD)g_NtSuspendThreadAddress)(ThreadHandle,PreviousSuspendCount);
	}
	ReloadNtSuspendThread = (NTSUSPENDTHREAD)(g_NtSuspendThreadAddress - 
		SystemKernelModuleBase + 
		(ULONG)ReloadNtosImageBase);
	//if (MmIsAddressValid(ReloadNtReadVirtualMemory))
	//{
	return ReloadNtSuspendThread(ThreadHandle,PreviousSuspendCount);
}
//////////////////////////////////////////////////////////////////////////
__declspec(naked)VOID HookObReferenceObjectByHandleZone()
{
	NOP_PROC;
	__asm jmp [s_lpOriginObReferenceObjectByHandleRet]
}
NTSTATUS
	NewObReferenceObjectByHandle (
	__in HANDLE Handle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__out PVOID *Object,
	__out_opt POBJECT_HANDLE_INFORMATION HandleInformation
	)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	OBREFERENCEOBJECTBYHANDLE pfnObReferenceObjectByHandle = (OBREFERENCEOBJECTBYHANDLE)HookObReferenceObjectByHandleZone;

	nStatus = pfnObReferenceObjectByHandle(Handle,
		DesiredAccess,
		ObjectType,
		AccessMode,
		Object,
		HandleInformation);
	if (IsFromGameProcess())
	{
		if (ObjectType == *PsProcessType)
		{
			if ((PEPROCESS)Object == g_pProtectProcess)
			{
				ObDereferenceObject(Object);
				return STATUS_INVALID_HANDLE;
			}
		}
	}
	return nStatus;
}
BOOL HookObReferenceObjectByHandle()
{
	s_OriginObReferenceObjectByHandle =
		GetExortedFunctionAddress(L"ObReferenceObjectByHandle");
	if (s_OriginObReferenceObjectByHandle == 0)
	{
		CodeVprint("HookObReferenceObjectByHandle failed..\n");
		return FALSE;
	}
	return HookFunctionByHeaderAddress((DWORD)NewObReferenceObjectByHandle,
		s_OriginObReferenceObjectByHandle,
		HookObReferenceObjectByHandleZone,
		&PatchObReferenceObjectByHandleLen,
		&s_lpOriginObReferenceObjectByHandleRet);
}
VOID UnhookObReferenceObjectByHandle()
{
	UnHookFunctionByHeaderAddress(s_OriginObReferenceObjectByHandle,HookObReferenceObjectByHandleZone,PatchObReferenceObjectByHandleLen);
}
//////////////////////////////////////////////////////////////////////////

__declspec(naked)VOID NtUserSetWindowsHookExZone()
{
	NOP_PROC;
	__asm jmp [lpSetWindowsHookExRet]
}
PVOID __stdcall NewNtUserSetWindowsHookEx(
	ULONG Mod, 
	PUNICODE_STRING ModuleName, 
	DWORD ThreadId, 
	int HookId, 
	PVOID HookProc, 
	DWORD dwFlags)
{
	if (IsFromGameProcess())
	{
		if (ThreadId == 0)
		{
			//游戏要设置全局消息钩子,返回空
			CodeVprint("Game want to set global msg hook!");
			return NULL;
		}
	}
	return  ((NTUSHERSETWINDOWSHOOKEX)NtUserSetWindowsHookExZone)(Mod,ModuleName,ThreadId,HookId,HookProc,dwFlags);
}
BOOL HookNtUserSetWindowsHookEx()
{
	BOOL bRet = FALSE;
	PEPROCESS eprocess_explorer;

	WPON();
	if (LookupProcessByName("explorer.exe",&eprocess_explorer) == STATUS_SUCCESS)
	{
		ExplorerProcess = eprocess_explorer;
		KeAttachProcess(eprocess_explorer);
		bRet = HookFunctionByHeaderAddress((DWORD)NewNtUserSetWindowsHookEx,
			g_RealNtUserSetWindowsHookExAddress,
			NtUserSetWindowsHookExZone,
			&patchNtUserWindowsHookExLen,
			&lpSetWindowsHookExRet
			);
		KeDetachProcess();
		CodeVprint("Hook usermessage success\r\n");

	}
	return bRet;
}
///*  */
VOID UnhookNtUserSetWindowsHookEx()
{
	KeAttachProcess(ExplorerProcess);
	UnHookFunctionByHeaderAddress(g_RealNtUserSetWindowsHookExAddress,NtUserSetWindowsHookExZone,patchNtUserWindowsHookExLen);
	KeDetachProcess();
}


//////////////////////////////////////////////////////////////////////////
//
/**/
__declspec(naked)VOID UserGetMessageZone()
{
	NOP_PROC;
	__asm jmp [lpUserGetMessageRet]
}

__declspec(naked)VOID UserPeekMessageZone()
{
	NOP_PROC;
	__asm jmp [lpUserPeekMessageRet]
}

BOOL HookUserMessage()
{
	PSERVICE_DESCRIPTOR_TABLE pOriginShadowTable;
	PEPROCESS eprocess_explorer;
	ULONG uReloadGetMessageAddress,uReloadPeekMessageAddress;
	uReloadGetMessageAddress = g_RealNtUserGetMessageAddress - SystemWin32kBase + (ULONG)ReloadWin32kImageBase;
	uReloadPeekMessageAddress = g_RealNtUserPeekMessageAddress - SystemWin32kBase + (ULONG)ReloadWin32kImageBase;
	if (!MmIsAddressValid((PVOID)uReloadGetMessageAddress) ||
		!MmIsAddressValid(((PVOID)uReloadPeekMessageAddress)))
	{
		return FALSE;
	}
	pOriginShadowTable = (PSERVICE_DESCRIPTOR_TABLE)GetShadowTableAddress();
	if (pOriginShadowTable == NULL)
	{
		return FALSE;
	}
	lpUserGetMessageRet = (PVOID)(g_RealNtUserGetMessageAddress + 7);
	lpUserPeekMessageRet = (PVOID)(g_RealNtUserPeekMessageAddress + 7);
	WPOFF();
	RtlCopyMemory((BYTE*)&UserGetMessageZone,(BYTE*)uReloadGetMessageAddress,7);
	RtlCopyMemory((BYTE*)&UserPeekMessageZone,(BYTE*)uReloadPeekMessageAddress,7);
	WPON();
	if (LookupProcessByName("explorer.exe",&eprocess_explorer) == STATUS_SUCCESS)
	{
		ExplorerProcess = eprocess_explorer;
		KeAttachProcess(eprocess_explorer);
		WPOFF();
		InterlockedExchange(&pOriginShadowTable[1].ServiceTable[0x1a5],(LONG)UserGetMessageZone);
		InterlockedExchange(&pOriginShadowTable[1].ServiceTable[0x1da],(LONG)UserPeekMessageZone);
		WPON();
		KeDetachProcess();
		CodeVprint("Hook usermessage success\r\n");
		return TRUE;
	}
	return FALSE;
}

VOID UnhookUserMessage()
{
	PSERVICE_DESCRIPTOR_TABLE pOriginShadowTable;
	pOriginShadowTable = (PSERVICE_DESCRIPTOR_TABLE)GetShadowTableAddress();
	if (pOriginShadowTable == NULL)
	{
		return;
	}
	KeAttachProcess(ExplorerProcess);
	WPOFF();
	InterlockedExchange(&(LONG)pOriginShadowTable[1].ServiceTable[0x1a5],(LONG)g_RealNtUserGetMessageAddress);
	InterlockedExchange(&(LONG)pOriginShadowTable[1].ServiceTable[0x1da],(LONG)g_RealNtUserPeekMessageAddress);
	WPON();
	KeDetachProcess();
}
/*  */

/*
__declspec(naked)VOID GdiBitBltZone()
{
	NOP_PROC;
	__asm jmp [lpGdiBitBltRet]
}
/ *  * /
__declspec(naked)VOID GdiStrechBltZone()
{
	NOP_PROC;
	__asm jmp [lpGdiStrechBltRet]
}

/ *  * /
BOOL HookGdiBlt()
{
	PSERVICE_DESCRIPTOR_TABLE pOriginShadowTable;
	PEPROCESS eprocess_explorer;
	ULONG uReloadGdiBitBltAddress,uReloadGdiStretchBltAddress;
	uReloadGdiBitBltAddress = g_RealNtGdiBitBltAddress - SystemWin32kBase + (ULONG)ReloadWin32kImageBase;
	uReloadGdiStretchBltAddress = g_RealNtGdiStretchBltAddress - SystemWin32kBase + (ULONG)ReloadWin32kImageBase;
	if (!MmIsAddressValid((PVOID)uReloadGdiBitBltAddress) ||
		!MmIsAddressValid(((PVOID)uReloadGdiStretchBltAddress)))
	{
		return FALSE;
	}
	pOriginShadowTable = (PSERVICE_DESCRIPTOR_TABLE)GetShadowTableAddress();
	if (pOriginShadowTable == NULL)
	{
		return FALSE;
	}
	lpGdiBitBltRet = (PVOID)(g_RealNtGdiBitBltAddress + 8);
	/ * 这个函数可不能搞8个字节， * /
	lpGdiStrechBltRet = (PVOID)(g_RealNtGdiStretchBltAddress + 6);
	WPOFF();
	RtlCopyMemory((BYTE*)&GdiBitBltZone,(BYTE*)uReloadGdiBitBltAddress,8);
	RtlCopyMemory((BYTE*)&GdiStrechBltZone,(BYTE*)uReloadGdiStretchBltAddress,6);
	WPON();
	if (LookupProcessByName("explorer.exe",&eprocess_explorer) == STATUS_SUCCESS)
	{
		ExplorerProcess = eprocess_explorer;
		KeAttachProcess(eprocess_explorer);
		WPOFF();
		InterlockedExchange(&pOriginShadowTable[1].ServiceTable[0xd],(LONG)GdiBitBltZone);
		InterlockedExchange(&pOriginShadowTable[1].ServiceTable[0x124],(LONG)GdiStrechBltZone);
		WPON();
		KeDetachProcess();
		CodeVprint(("Hook GdiBlt success\r\n"));
		return TRUE;
	}
	return FALSE;
}
/ *  * /
VOID UnhookGdiBlt()
{
	PSERVICE_DESCRIPTOR_TABLE pOriginShadowTable;
	pOriginShadowTable = (PSERVICE_DESCRIPTOR_TABLE)GetShadowTableAddress();
	if (pOriginShadowTable == NULL)
	{
		return;
	}
	KeAttachProcess(ExplorerProcess);
	WPOFF();
	InterlockedExchange(&(LONG)pOriginShadowTable[1].ServiceTable[0xd],(LONG)g_RealNtGdiBitBltAddress);
	InterlockedExchange(&(LONG)pOriginShadowTable[1].ServiceTable[0x124],(LONG)g_RealNtGdiStretchBltAddress);
	WPON();
	KeDetachProcess();
}*/
/********************************************************************************/
__declspec(naked)VOID HookOriginKiFastCallEntryZone()
{
	NOP_PROC;
	__asm jmp [lpHookOriginKiFastCallEntryRet]
}
//摆设。。
__declspec(naked)VOID HookNewKiFastCallEntryZone()
{
	__asm
	{
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		jmp [lpHookNewKiFastCallEntryRet]
	}
}

//过滤函数，很重要啦
ULONG __stdcall FilterKiFastCallEntryWinXP(ULONG Index,
	ULONG FunctionAddress,
	PVOID KiServiceTable)
{
	if (KiServiceTable == (PVOID)KeServiceDescriptorTable->ServiceTable)
	{
		if (122 == Index)
		{
			return (ULONG)NewNtOpenProcess;
		}
		else if (186 == Index)
		{
			return (ULONG)NewNtReadVirtualMemory;
		}
		else if (277 == Index)
		{
			return (ULONG)NewNtWriteVirtualMemory;
		} 
		else if (53 == Index)
		{
			return (ULONG)NewNtCreateThread;
		}
		else if (68 == Index)
		{
			return (ULONG)NewNtDuplicateObject;
		}
		else if (253 == Index)
		{
			return (ULONG)NewNtSuspendProcess;
		}
		else if (254 == Index)
		{
			return (ULONG)NewNtSuspendThread;
		}
	}
	//这里处理影子表
	return FunctionAddress;
}
__declspec(naked)VOID NewKiFastCallEntryProcWinXP()
{
	// 80542610 8b3f            mov     edi,dword ptr [edi]
	// 80542612 8b1c87          mov     ebx,dword ptr [edi+eax*4]
	// b9ef6916 2be1            sub     esp,ecx
	// b9ef6918 c1e902          shr     ecx,2
	__asm
	{
		//PUSHAD的入栈顺序是:EAX、ECX、EDX、EBX、ESP、EBP、ESI、EDI
		mov edi,edi
		pushfd
		pushad

		push edi
		push ebx
		push eax
		call FilterKiFastCallEntryWinXP
		mov dword ptr [esp+10h],eax
		popad
		popfd
		sub esp,ecx
		shr ecx,2
		jmp [lpHookNewKiFastCallEntryRet]
	}
}
//

BOOL HookNewKiFastCallEntry()
{
	BOOLEAN bRetOK=FALSE;
	ULONG i;
	PUCHAR p;
	UCHAR JmpCode[5]={0xe9,0,0,0,0};
	ULONG ulSizeProc;
	g_OriginKiFastCallEntryAddress = GetOriginKiFastCallEntryAddress();
	if (!g_OriginKiFastCallEntryAddress)
	{
		CodeVprint("GetOriginKiFastCallEntryAddress failed\r\n");
		return FALSE;
	}
	CodeVprint("GetOriginKiFastCallEntryAddress success\r\n");
	g_NewKiFastCallEntryAddress=g_OriginKiFastCallEntryAddress - SystemKernelModuleBase + (ULONG)ReloadNtosImageBase;
	if (!MmIsAddressValid((PVOID)g_NewKiFastCallEntryAddress))
	{
		return FALSE;
	}
		p=(PUCHAR)g_NewKiFastCallEntryAddress;
		ulSizeProc = SizeOfProc((PVOID)g_NewKiFastCallEntryAddress);
		for (i = 0;i < ulSizeProc;i++,p++)
		{
			if (*(p)==0x8b&&
				*(p+1)==0x3f&&
				*(p+2)==0x8b&&
				*(p+3)==0x1c&&
				*(p+4)==0x87)
			{
				bRetOK=TRUE;
				g_HookNewKiFastCallEntryAddress = (ULONG)(p + 5);
				lpHookNewKiFastCallEntryRet = (PVOID)(g_HookNewKiFastCallEntryAddress+5);
				break;
			}
		}
		if (!bRetOK)
		{
			return FALSE;
		}
		*(PULONG)(JmpCode+1)=(ULONG)NewKiFastCallEntryProcWinXP-g_HookNewKiFastCallEntryAddress-5;
		WPOFF();
		RtlCopyMemory((PUCHAR)HookNewKiFastCallEntryZone,(PUCHAR)g_HookNewKiFastCallEntryAddress,5);
		RtlCopyMemory((PUCHAR)g_HookNewKiFastCallEntryAddress,JmpCode,5);
		WPON();
		//开始WDMSR,写入新地址
		/*KiRestoreFastSyscallReturnState();*/
		//然后hook老函数
		bRetOK = HookFunctionByHeaderAddress(g_NewKiFastCallEntryAddress,
			g_OriginKiFastCallEntryAddress,
			HookOriginKiFastCallEntryZone,
			&PatchOriginKiFastCallEntryLen,
			&lpHookOriginKiFastCallEntryRet);
	return bRetOK;
}

VOID UnHookNewKiFastCallEntry()
{
	UnHookFunctionByHeaderAddress(g_OriginKiFastCallEntryAddress,
		HookOriginKiFastCallEntryZone,
		PatchOriginKiFastCallEntryLen);
	// 	WaitMicroSecond(200);
	// 	WProtectOff();
	// 	RtlCopyMemory((PUCHAR)g_HookNewKiFastCallEntryAddress,(PUCHAR)NewKiFastCallEntryZone,5);
	// 	WProtectOn();
}


// __declspec(naked)VOID  HookZone1()
//{
//	NOP_PROC;
//}
// __declspec(naked)VOID  HookZone2()
// {
//	 NOP_PROC;
// }
// __declspec(naked)VOID  HookZone3()
// {
//	 NOP_PROC;
// }
// __declspec(naked)VOID  HookZone4()
// {
//	 NOP_PROC;
// }
// __declspec(naked)VOID  HookZone5()
// {
//	 NOP_PROC;
// }
// __declspec(naked)VOID  HookZone6()
// {
//	 NOP_PROC;
// }
// __declspec(naked)VOID  HookZone7()
// {
//	 NOP_PROC;
// }
// __declspec(naked)VOID  HookZone8()
// {
//	 NOP_PROC;
// }
// ULONG g_ulKeWaitForSingleObject;
// ULONG g_ulKeWaitForMultipleObjects;
// ULONG g_ulKeDelayExecutionThread;
// ULONG g_ulKeTerminateThread;
// ULONG g_ulKeRemoveQueue;
// /*ULONG ulKeWaitForGate;*/
// ULONG g_ulKeAttachProcess;
// ULONG g_ulKeStackAttachProcess;
// ULONG g_ulReloadKeWaitForSingleObject;
// ULONG g_ulReloadKeWaitForMultipleObjects;
// ULONG g_ulReloadKeDelayExecutionThread;
// ULONG g_ulReloadKeTerminateThread;
// ULONG g_ulReloadKeRemoveQueue;
// /*ULONG ulReloadKeWaitForGate;*/
// ULONG g_ulReloadKeAttachProcess;
// ULONG g_ulReloadKeStackAttachProcess;
//BOOL FuckKiSwapThread()
//{
//	//__asm int 3;
//	g_ulKeWaitForSingleObject = GetExortedFunctionAddress(L"KeWaitForSingleObject");
//	if (g_ulKeWaitForSingleObject == 0)
//	{
//		return FALSE;
//	}
//	g_ulReloadKeWaitForSingleObject = g_ulKeWaitForSingleObject - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	g_ulKeWaitForMultipleObjects = GetExortedFunctionAddress(L"KeWaitForMultipleObjects");
//	if (g_ulKeWaitForMultipleObjects == 0)
//	{
//		return FALSE;
//	}
//	g_ulReloadKeWaitForMultipleObjects = g_ulKeWaitForMultipleObjects - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	g_ulKeDelayExecutionThread = GetExortedFunctionAddress(L"KeDelayExecutionThread");
//	if (g_ulKeDelayExecutionThread == 0)
//	{
//		return FALSE;
//	}
//	g_ulReloadKeDelayExecutionThread = g_ulKeDelayExecutionThread - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	g_ulKeTerminateThread = GetExortedFunctionAddress(L"KeTerminateThread");
//	if (g_ulKeTerminateThread == 0)
//	{
//		return FALSE;
//	}
//	g_ulReloadKeTerminateThread = g_ulKeTerminateThread - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	g_ulKeRemoveQueue = GetExortedFunctionAddress(L"KeRemoveQueue");
//	if (g_ulKeRemoveQueue == 0)
//	{
//		return FALSE;
//	}
//	g_ulReloadKeRemoveQueue = g_ulKeRemoveQueue - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	//ulKeWaitForGate = GetExortedFunctionAddress(L"KeWaitForGate");
//	//if (ulKeWaitForGate == 0)
//	//{
//	//	return FALSE;
//	//}
//	//ulReloadKeWaitForGate = ulKeWaitForGate - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	g_ulKeAttachProcess = GetExortedFunctionAddress(L"KeAttachProcess");
//	if (g_ulKeAttachProcess == 0)
//	{
//		return FALSE;
//	}
//	g_ulReloadKeAttachProcess = g_ulKeAttachProcess - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	g_ulKeStackAttachProcess = GetExortedFunctionAddress(L"KeStackAttachProcess");
//	if (g_ulKeStackAttachProcess == 0)
//	{
//		return FALSE;
//	}
//	g_ulReloadKeStackAttachProcess = g_ulKeStackAttachProcess - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	HookFunctionByHeaderAddress(g_ulReloadKeWaitForSingleObject,
//		g_ulKeWaitForSingleObject,HookZone1,&patchlen1,&lpKeRet);
//	HookFunctionByHeaderAddress(g_ulReloadKeWaitForMultipleObjects,
//		g_ulKeWaitForMultipleObjects,HookZone2,&patchlen2,&lpKeRet);
//	//
//	HookFunctionByHeaderAddress(g_ulReloadKeDelayExecutionThread,
//		g_ulKeDelayExecutionThread,HookZone3,&patchlen3,&lpKeRet);
//	HookFunctionByHeaderAddress(g_ulReloadKeTerminateThread,
//		g_ulKeTerminateThread,HookZone4,&patchlen4,&lpKeRet);
//	//
//	HookFunctionByHeaderAddress(g_ulReloadKeRemoveQueue,
//		g_ulKeRemoveQueue,HookZone5,&patchlen5,&lpKeRet);
//	//HookFunctionByHeaderAddress(ulReloadKeWaitForGate,
//	//	ulKeWaitForGate,HookZone6,&patchlen6,&lpKeRet);
//	HookFunctionByHeaderAddress(g_ulReloadKeAttachProcess,
//		g_ulKeAttachProcess,HookZone7,&patchlen8,&lpKeRet);
//	HookFunctionByHeaderAddress(g_ulReloadKeStackAttachProcess,
//		g_ulKeStackAttachProcess,HookZone8,&patchlen8,&lpKeRet);
//	return TRUE;
//}
////
//VOID UnFuckKiSwapThread()
//{
//// 	ULONG ulKeWaitForSingleObject;
//// 	ULONG ulKeWaitForMultipleObjects;
//// 	ULONG ulKeDelayExecutionThread;
//// 	ULONG ulKeTerminateThread;
//// 	ULONG ulKeRemoveQueue;
//// 	/*ULONG ulKeWaitForGate;*/
//// 	ULONG ulKeAttachProcess;
//// 	ULONG ulKeStackAttachProcess;
//// 	ulKeWaitForSingleObject = GetExortedFunctionAddress(L"KeWaitForSingleObject");
//	if (g_ulKeWaitForSingleObject == 0)
//	{
//		return;
//	}
//	//ulReloadKeWaitForSingleObject = ulKeWaitForSingleObject - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	//ulKeWaitForMultipleObjects = GetExortedFunctionAddress(L"KeWaitForMultipleObjects");
//	if (g_ulKeWaitForMultipleObjects == 0)
//	{
//		return ;
//	}
//	//ulReloadKeWaitForMultipleObjects = ulKeWaitForMultipleObjects - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	//ulKeDelayExecutionThread = GetExortedFunctionAddress(L"KeDelayExecutionThread");
//	if (g_ulKeDelayExecutionThread == 0)
//	{
//		return ;
//	}
//	//ulReloadKeDelayExecutionThread = ulKeDelayExecutionThread - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	//ulKeTerminateThread = GetExortedFunctionAddress(L"KeTerminateThread");
//	if (g_ulKeTerminateThread == 0)
//	{
//		return ;
//	}
//	//ulReloadKeTerminateThread = ulKeTerminateThread - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	//ulKeRemoveQueue = GetExortedFunctionAddress(L"KeRemoveQueue");
//	if (g_ulKeRemoveQueue == 0)
//	{
//		return ;
//	}
//	//ulReloadKeRemoveQueue = ulKeRemoveQueue - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	//ulKeWaitForGate = GetExortedFunctionAddress(L"KeWaitForGate");
//	//if (ulKeWaitForGate == 0)
//	//{
//	//	return ;
//	//}
//	//ulReloadKeWaitForGate = ulKeWaitForGate - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	//ulKeAttachProcess = GetExortedFunctionAddress(L"KeAttachProcess");
//	if (g_ulKeAttachProcess == 0)
//	{
//		return ;
//	}
//	//ulReloadKeAttachProcess = ulKeAttachProcess - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	//ulKeStackAttachProcess = GetExortedFunctionAddress(L"KeStackAttachProcess");
//	if (g_ulKeStackAttachProcess == 0)
//	{
//		return ;
//	}
//	//ulReloadKeStackAttachProcess = ulKeStackAttachProcess - SystemKernelModuleBase+(ULONG)ReloadNtosImageBase;
//	UnHookFunctionByHeaderAddress(g_ulKeWaitForSingleObject,HookZone1,patchlen1);
//	UnHookFunctionByHeaderAddress(g_ulKeWaitForMultipleObjects,HookZone2,patchlen2);
//	UnHookFunctionByHeaderAddress(g_ulKeDelayExecutionThread,HookZone3,patchlen3);
//	UnHookFunctionByHeaderAddress(g_ulKeTerminateThread,HookZone4,patchlen4);
//	UnHookFunctionByHeaderAddress(g_ulKeRemoveQueue,HookZone5,patchlen5);
//	//UnHookFunctionByHeaderAddress(ulKeWaitForGate,HookZone6,patchlen6);
//	UnHookFunctionByHeaderAddress(g_ulKeAttachProcess,HookZone7,patchlen7);
//	UnHookFunctionByHeaderAddress(g_ulKeStackAttachProcess,HookZone8,patchlen8);
//}
//KeWaitForSingleObject
//KeWaitForMultipleObjects
//KeDelayExecutionThread
//KeTerminateThread
//KeRemoveQueue
//KeWaitForGate
//KeAttachProcess
//KeStackAttachProcess


