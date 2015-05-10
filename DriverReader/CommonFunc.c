#include "CommonFunc.h"

//////////////////////////////////////////////////////////////////////////
char *OwnName= "TianChen.exe";
//char *OwnName= "calc.exe";
ULONG g_GameProcessCount = 5;
char GameProcessName[][30]={"DNF.exe","TenSafe_1.exe","Client.exe","TenSafe.exe","TASLogin.exe"};

VOID WPOFF()  
{
	__asm
	{
		cli
			mov eax,cr0
			and eax,not 10000h
			mov cr0,eax
	}
}
//内存恢复，不可写/////////////////////////////////////////////////////
VOID WPON()  
{
	__asm
	{
		mov eax,cr0
			or eax,10000h
			mov cr0,eax
			sti
	}
}

BOOL IsFromGameProcess()
{
	BOOL bRet = FALSE;
	ULONG i=0;
	PCHAR ProcessName = PsGetProcessImageFileName(PsGetCurrentProcess());
	if (ProcessName)
	{
		for (i=0;i<g_GameProcessCount;i++)
		{
			if (_stricmp(ProcessName,GameProcessName[i])==0)
			{
				bRet = TRUE;
				break;
			}
		}
	}
	return bRet;
}
/*  */
BOOL IsOurProcess(PEPROCESS process)
{
	PCHAR ProcessName = PsGetProcessImageFileName(process);
	if (ProcessName)
	{
		if (_stricmp(ProcessName, OwnName)== 0)
		{
			//CodeVprint("Candy calling dnf!\r\n");
			return TRUE;
		}
	}
	return FALSE;
}
/*  */
ULONG GetExortedFunctionAddress(PWCHAR FunctionName)
{
	UNICODE_STRING UniFunctionName;
	RtlInitUnicodeString(&UniFunctionName,FunctionName);
	return (ULONG)MmGetSystemRoutineAddress(&UniFunctionName);
}
__inline ULONG CR4()
{
	// mov eax, cr4
	__asm _emit 0x0F __asm _emit 0x20 __asm _emit 0xE0
}
VALIDITY_CHECK_STATUS MmIsAddressValidExNotPae(
	IN PVOID Pointer
	)
{
	VALIDITY_CHECK_STATUS  Return = VCS_INVALID;
	MMPTE* Pde;
	MMPTE* Pte;
	MMPTE pte;

	Pde = MiGetPdeAddress(Pointer);

	//KdPrint(("PDE is 0x%08x\n", Pde));
	if( Pde->u.Hard.Valid )
	{
		//KdPrint(("PDE entry is valid, PTE PFN=%08x\n", Pde->u.Hard.PageFrameNumber));

		Pte = MiGetPteAddress(Pointer);

		//KdPrint(("PTE is 0x%08x\n", Pte));
		if( Pte->u.Hard.Valid )
		{
			//KdPrint(("PTE entry is valid, PFN=%08x\n", Pte->u.Hard.PageFrameNumber));
			Return = VCS_VALID;
		}
		else
		{
			//
			// PTE is not valid
			//

			pte = *Pte;

			//KdPrint(("Got invalid PTE [%08x]: Proto=%d,Transition=%d,Protection=0x%x,PageFilePFN=0x%x\n",
			//	pte.u.Long,
			//	pte.u.Soft.Prototype,
			//	pte.u.Soft.Transition,
			//	pte.u.Soft.Protection,
			//	pte.u.Soft.PageFileHigh));

			if( pte.u.Long )
			{
				if( pte.u.Soft.Prototype == 1 )
				{
					//KdPrint(("PTE entry is not valid, points to prototype PTE.\n"));

					// more accurate check should be performed here for pointed prototype PTE!

					Return = VCS_PROTOTYPE;
				}
				else  // not a prototype PTE
				{
					if( pte.u.Soft.Transition != 0 )
					{
						//
						// This is a transition page. Consider it invalid.
						//

						//KdPrint(("PTE entry is not valid, points to transition page.\n"));

						Return = VCS_TRANSITION;
					}
					else if (pte.u.Soft.PageFileHigh == 0)
					{
						//
						// Demand zero page
						//

						//KdPrint(("PTE entry is not valid, points to demand-zero page.\n"));

						Return = VCS_DEMANDZERO;
					}
					else
					{
						//
						// Pagefile PTE
						//

						if( pte.u.Soft.Transition == 0 )
						{
							//KdPrint(("PTE entry is not valid, VA is paged out (PageFile offset=%08x)\n",
							//	pte.u.Soft.PageFileHigh));

							Return = VCS_PAGEDOUT;
						}
						else
						{
							//KdPrint(("PTE entry is not valid, Refault\n"));
						}
					}
				}
			}
			else
			{
				//KdPrint(("PTE entry is completely invalid\n"));
			}
		}
	}
	else
	{
		//KdPrint(("PDE entry is not valid\n"));
	}

	return Return;
}
VALIDITY_CHECK_STATUS MmIsAddressValidExPae(
	IN PVOID Pointer
	)
{
	VALIDITY_CHECK_STATUS Return = VCS_INVALID;
	MMPTE_PAE* Pde;
	MMPTE_PAE* Pte;
	MMPTE_PAE pte;

	Pde = MiGetPdeAddressPae(Pointer);

	//KdPrint(("PDE is at 0x%08x\n", Pde));
	if( Pde->u.Hard.Valid )
	{
		//KdPrint(("PDE entry is valid, PTE PFN=%08x\n", Pde->u.Hard.PageFrameNumber));

		if( Pde->u.Hard.LargePage != 0 )
		{
			//
			// This is a large 2M page
			//

			//KdPrint(("! PDE points to large 2M page\n"));

			Pte = Pde;
		}
		else
		{
			//
			// Small 4K page
			//

			// Get its PTE
			Pte  = MiGetPteAddressPae(Pointer);
		}

		//KdPrint(("PTE is at 0x%08x\n", Pte));
		if( Pte->u.Hard.Valid )
		{
			//KdPrint(("PTE entry is valid, PFN=%08x\n", Pte->u.Hard.PageFrameNumber));

			Return = VCS_VALID;
		}
		else
		{
			//
			// PTE is not valid
			//

			pte = *Pte;

			//KdPrint(("Got invalid PTE [%08x%08x]\n", pte.u.Long.HighPart, pte.u.Long.LowPart));

			if( pte.u.Long.LowPart == 0 )
			{
				//KdPrint(("PTE entry is completely invalid (page is not committed or is within VAD tree)\n"));
			}
			else
			{
				if( pte.u.Soft.Prototype == 1 )
				{
					// 					//KdPrint(("PTE entry is not valid, points to prototype PTE. Protection=%x[%s], ProtoAddress=%x\n",
					// 						(ULONG)pte.u.Proto.Protection,
					// 						MiPageProtectionString((UCHAR)pte.u.Proto.Protection),
					// 						(ULONG)pte.u.Proto.ProtoAddress));

					// more accurate check should be performed here for pointed prototype PTE!

					Return = VCS_PROTOTYPE;
				}
				else  // not a prototype PTE
				{
					if( pte.u.Soft.Transition != 0 )
					{
						//
						// This is a transition page.
						//

						// 						//KdPrint(("PTE entry is not valid, points to transition page. PFN=%x, Protection=%x[%s]\n",
						// 							(ULONG)pte.u.Trans.PageFrameNumber,
						// 							(ULONG)pte.u.Trans.Protection,
						// 							MiPageProtectionString((UCHAR)pte.u.Trans.Protection)));

						Return = VCS_TRANSITION;
					}
					else if (pte.u.Soft.PageFileHigh == 0)
					{
						//
						// Demand zero page
						//

						// 						//KdPrint(("PTE entry is not valid, points to demand-zero page. Protection=%x[%s]\n",
						// 							(ULONG)pte.u.Soft.Protection,
						// 							MiPageProtectionString((UCHAR)pte.u.Soft.Protection)));

						Return = VCS_DEMANDZERO;
					}
					else
					{
						//
						// Pagefile PTE
						//

						if( pte.u.Soft.Transition == 0 )
						{
							// 							//KdPrint(("PTE entry is not valid, VA is paged out. PageFile Offset=%08x, Protection=%x[%s]\n",
							// 								(ULONG)pte.u.Soft.PageFileHigh,
							// 								(ULONG)pte.u.Soft.Protection,
							// 								MiPageProtectionString((UCHAR)pte.u.Soft.Protection)));

							Return = VCS_PAGEDOUT;
						}
						else
						{
							//KdPrint(("PTE entry is not valid, Refault\n"));
						}
					}
				}
			}
		}
	}
	else
	{
		//KdPrint(("PDE entry is not valid\n"));
	}

	return Return;
}
VALIDITY_CHECK_STATUS MiIsAddressValidEx(
	IN PVOID Pointer
	)
{
	if( CR4() & PAE_ON ) {
		return MmIsAddressValidExPae(Pointer);
	}
	else {
		return MmIsAddressValidExNotPae(Pointer);
	}
}
BOOL MmIsAddressValidEx(
	IN PVOID Pointer
	)
{
	VALIDITY_CHECK_STATUS MmRet;
	ULONG ulTry;

	if (!ARGUMENT_PRESENT(Pointer) ||
		!Pointer){
		return FALSE;
	}
	/*
	//VCS_TRANSITION、VCS_PAGEDOUT内存居然是这样子~~擦~

	lkd> dd f8ad5ad8
	f8ad5ad8  ???????? ???????? ???????? ????????
	f8ad5ae8  ???????? ???????? ???????? ????????
	f8ad5af8  ???????? ???????? ???????? ????????
	f8ad5b08  ???????? ???????? ???????? ????????
	f8ad5b18  ???????? ???????? ???????? ????????
	f8ad5b28  ???????? ???????? ???????? ????????
	f8ad5b38  ???????? ???????? ???????? ????????
	f8ad5b48  ???????? ???????? ???????? ????????
	*/
	MmRet = MiIsAddressValidEx(Pointer);
	if (MmRet != VCS_VALID){
		return FALSE;
	}
	return TRUE;
}
/************************************************************************/
//对源地址的数据进行安全拷贝，再对拷贝后的数据进行操作
//
/************************************************************************/
NTSTATUS SafeCopyMemory(PVOID SrcAddr, PVOID DstAddr, ULONG Size)
{
	PMDL  pSrcMdl, pDstMdl;
	PUCHAR pSrcAddress, pDstAddress;
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	ULONG r;
	BOOL bInit = FALSE;

	pSrcMdl = IoAllocateMdl(SrcAddr, Size, FALSE, FALSE, NULL);
	if (MmIsAddressValidEx(pSrcMdl))
	{
		MmBuildMdlForNonPagedPool(pSrcMdl);
		pSrcAddress = (PUCHAR)MmGetSystemAddressForMdlSafe(pSrcMdl, NormalPagePriority);
		if (MmIsAddressValidEx(pSrcAddress))
		{
			pDstMdl = IoAllocateMdl(DstAddr, Size, FALSE, FALSE, NULL);
			if (MmIsAddressValidEx(pDstMdl))
			{
				__try
				{
					MmProbeAndLockPages(pDstMdl, KernelMode, IoWriteAccess);
					pDstAddress = (PUCHAR)MmGetSystemAddressForMdlSafe(pDstMdl, NormalPagePriority);
					if (MmIsAddressValidEx(pDstAddress))
					{
						RtlZeroMemory(pDstAddress,Size);
						RtlCopyMemory(pDstAddress, pSrcAddress, Size);
						st = STATUS_SUCCESS;
					}
					MmUnlockPages(pDstMdl);
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{                 
					if (pDstMdl) MmUnlockPages(pDstMdl);

					if (pDstMdl) IoFreeMdl(pDstMdl);

					if (pSrcMdl) IoFreeMdl(pSrcMdl);

					return GetExceptionCode();
				}
				IoFreeMdl(pDstMdl);
			}
		}            
		IoFreeMdl(pSrcMdl);
	}
	return st;
}
/**/
ULONG GetOriginKiFastCallEntryAddress()
{
	ULONG uKiFastCallEntry=0;
	__asm
	{
		pushad
			mov ecx,0x176
			rdmsr
			mov uKiFastCallEntry,eax
			popad
	}
	return uKiFastCallEntry;
}

/*通过ZwQuerySystemInformation获取驱动信息*/
PVOID GetKernelModuleInfo(CHAR *DriverName)
{
	NTSTATUS status;
	ULONG ulSize;
	PMODULES pModuleList;
	char *lpszKernelName=NULL;
	ULONG i;
	PSYSTEM_MODULE_INFORMATION pSmi = NULL;
	ULONG uCount;
	PVOID pDriverBase = NULL;
	status=ZwQuerySystemInformation(
		11,
		NULL,
		0,
		&ulSize
		);
	if (status!=STATUS_INFO_LENGTH_MISMATCH)
	{
		return NULL;
	}
	pModuleList=(PMODULES)ExAllocatePool(NonPagedPool,ulSize);
	if (!pModuleList)
	{
		return NULL;
	}
	status=ZwQuerySystemInformation(
		11,
		pModuleList,
		ulSize,
		&ulSize
		);
	if (!NT_SUCCESS(status))
	{
		CodeVprint("ZwQuerySystemInformation error:0X%x\r\n",status);
		ExFreePool(pModuleList);
		return NULL;
	}
	uCount = pModuleList->ulCount;
	pSmi = (PSYSTEM_MODULE_INFORMATION)((ULONG)pModuleList + sizeof(ULONG));
	for (i = 0; i<uCount;i++)
	{
		lpszKernelName = pSmi->ModuleNameOffset+pSmi->ImageName;
		if (_stricmp(lpszKernelName,DriverName) == 0)
		{
			pDriverBase = (PVOID)(pSmi->Base);
			break;
		}
		pSmi++;
	}
	if (pModuleList)
	{
		ExFreePool(pModuleList);
	}
	return pDriverBase;
}

NTSTATUS LookupProcessByName(
	IN PCHAR pcProcessName,
	OUT PEPROCESS *pEprocess
	)
{ 
	NTSTATUS	status;
	ULONG		uCount = 0;
	ULONG		uLength = 0;
	PLIST_ENTRY	pListActiveProcess;
	PEPROCESS	pCurrentEprocess = NULL;
	ULONG ulNextProcess = NULL;
	ULONG g_Offset_Eprocess_Flink;
	char lpszProName[100];
	char *lpszAttackProName = NULL;


	if (!ARGUMENT_PRESENT(pcProcessName) || !ARGUMENT_PRESENT(pEprocess))
	{
		return STATUS_INVALID_PARAMETER;
	}
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	uLength = strlen(pcProcessName);

	//WinVer = GetWindowsVersion();
	switch(WinVersion)
	{
	case WINDOWS_VERSION_XP:
		g_Offset_Eprocess_Flink = 0x88;
		break;
	case WINDOWS_VERSION_7_7600_UP:
	case WINDOWS_VERSION_7_7000:
		g_Offset_Eprocess_Flink = 0xb8;
		break;
	case WINDOWS_VERSION_VISTA_2008:
		g_Offset_Eprocess_Flink = 0x0a0;
		break;
	case WINDOWS_VERSION_2K3_SP1_SP2:
		g_Offset_Eprocess_Flink = 0x98;
		break;
	case WINDOWS_VERSION_2K3:
		g_Offset_Eprocess_Flink = 0x088;
		break;
	}
	if (!g_Offset_Eprocess_Flink){
		return STATUS_UNSUCCESSFUL;
	}

	pCurrentEprocess = PsGetCurrentProcess();
	ulNextProcess = pCurrentEprocess;
	__try
	{
		memset(lpszProName,0,sizeof(lpszProName));
		if (uLength > 15)
		{
			strncat(lpszProName,pcProcessName,15);
		}
		while(1)
		{
			lpszAttackProName = NULL;
			lpszAttackProName = (char *)PsGetProcessImageFileName(pCurrentEprocess);

			if (uLength > 15)
			{
				if (lpszAttackProName &&
					strlen(lpszAttackProName) == uLength)
				{
					if(_strnicmp(lpszProName,lpszAttackProName, uLength) == 0)
					{
						*pEprocess = pCurrentEprocess;
						status = STATUS_SUCCESS;
						break;
					}
				}
			}
			else
			{
				if (lpszAttackProName &&
					strlen(lpszAttackProName) == uLength)
				{
					if(_strnicmp(pcProcessName,lpszAttackProName, uLength) == 0)
					{
						*pEprocess = pCurrentEprocess;
						status = STATUS_SUCCESS;
						break;
					}
				}
			}
			if ((uCount >= 1) && (ulNextProcess == pCurrentEprocess))
			{
				*pEprocess = 0x00000000;
				status = STATUS_NOT_FOUND;
				break;
			}
			pListActiveProcess = (LIST_ENTRY *)((ULONG)pCurrentEprocess + g_Offset_Eprocess_Flink);
			(ULONG)pCurrentEprocess = (ULONG)pListActiveProcess->Flink;
			(ULONG)pCurrentEprocess = (ULONG)pCurrentEprocess - g_Offset_Eprocess_Flink;
			uCount++;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		CodeVprint("LookupProcessByName:%08x\r\n",GetExceptionCode());
		status = STATUS_NOT_FOUND;
	}
	return status;
}

PSYSTEM_HANDLE_INFORMATION_EX GetInfoTable(OUT PULONG nSize)
{
	PVOID Buffer;
	NTSTATUS status;
	Buffer =ExAllocatePool(PagedPool,0x1000);
	status = ZwQuerySystemInformation(SystemHandleInformation, Buffer, 0x1000, nSize);
	ExFreePool(Buffer);
	if(status == STATUS_INFO_LENGTH_MISMATCH)
	{
		Buffer = ExAllocatePool(NonPagedPool, *nSize);
		status = ZwQuerySystemInformation(SystemHandleInformation, Buffer, *nSize, NULL);
		if(NT_SUCCESS(status))
		{
			return (PSYSTEM_HANDLE_INFORMATION_EX)Buffer;
		}
	}
	return (PSYSTEM_HANDLE_INFORMATION_EX)0;
}

//擦除全局进程句柄表,这里得到句柄表的句柄
NTSTATUS GetPspCidTable(PHANDLE_TABLE *pPspHandleAddr)
{
    /*
     kd> dd PspCidTable
     805649c0  e1000c88 00000002 00000000 00000000
    *///得到本机的PspTable地址为 805649c0

    /*另外，通过搜索PsLookupProcessByProcessId也可以
    u PsLookupProcessByProcessId

    805d40de 8bff            mov     edi,edi
    805d40e0 55              push    ebp
    805d40e1 8bec            mov     ebp,esp
    805d40e3 53              push    ebx
    805d40e4 56              push    esi
    805d40e5 64a124010000    mov     eax,dword ptr fs:[00000124h]
    805d40eb ff7508          push    dword ptr [ebp+8]
    805d40ee 8bf0            mov     esi,eax
    805d40f0 ff8ed4000000    dec     dword ptr [esi+0D4h]
    805d40f6 ff35c0495680    push    dword ptr [nt!PspCidTable (805649c0)]
    805d40fc e859ad0300      call    nt!ExMapHandleToPointer (8060ee5a)
    805d4101 8bd8            mov     ebx,eax
    805d4103 85db            test    ebx,ebx
    */
    NTSTATUS Status = STATUS_SUCCESS;
    char * Addr_PsLookupProcessByProcessId = 0;
    int i = 0;
    char Findcode[] = { 0xff, 0x8e, 0xff, 0x35}; // WIN XP SP3
    ULONG Addr_PspCidTable = 0;

    //DbgPrint("进入函数\n");
    //uStartAddress=PsLookupProcessByProcessId;
    //DbgPrint("uStartAddress%x\n",uStartAddress);

    Addr_PsLookupProcessByProcessId = ( char * ) GetExortedFunctionAddress( L"PsLookupProcessByProcessId" );
    for( i = 0; i < 100; i ++ )
    {
        if( Addr_PsLookupProcessByProcessId[i] == Findcode[0] &&
                Addr_PsLookupProcessByProcessId[i + 1] == Findcode[1] &&
                Addr_PsLookupProcessByProcessId[i + 6] == Findcode[2] &&
                Addr_PsLookupProcessByProcessId[i + 7] == Findcode[3]
          )
        {
            Addr_PspCidTable = * ( ULONG* )( &Addr_PsLookupProcessByProcessId[i + 8] );
            break;
        }
    }

    *pPspHandleAddr = ( PHANDLE_TABLE )Addr_PspCidTable;

    //CodeVprint( "PspCidTable地址:%x\n", * ( PULONG ) pPspHandleAddr );
    return Status;
}
/*睡眠指定秒的时间*/
VOID Delay(ULONG uMSeconds)
{
	LARGE_INTEGER interval;
	interval.QuadPart = (uMSeconds * (-10)*1000);
	KeDelayExecutionThread(KernelMode,FALSE,&interval);
}