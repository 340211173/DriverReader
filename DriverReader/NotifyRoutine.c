#include "NotifyRoutine.h"
/* 控制系统线程启动停止 */
PETHREAD RemoveThread = NULL;
BOOL bRemove = FALSE;
//
ULONG g_PspSetCreateProcessNotifyRoutine;
ULONG g_PspCreateThreadNotifyRoutine;
ULONG g_PspSetLoadImageNotifyRoutine;
PVOID TpModuleBase = NULL;

ULONG GetPspCreateProcessNotifyRoutineAddress()
{
//805d0cb3 7464            je      nt!PsSetCreateProcessNotifyRoutine+0x73 (805d0d19)
//nt!PsSetCreateProcessNotifyRoutine+0xf:
//805d0cb5 bf404a5680      mov     edi,offset nt!PspCreateProcessNotifyRoutine (80564a40)
//
//nt!PsSetCreateProcessNotifyRoutine+0x14:
//805d0cba 57              push    edi
//805d0cbb e852d70300      call    nt!ExReferenceCallBackBlock (8060e412)
	ULONG ulPsSetCreateProcessNotifyRoutine;
	PUCHAR p;
	ULONG ulSize;
	ULONG i;
	ULONG ulAddress;
	BOOL bFind = FALSE;
	ulPsSetCreateProcessNotifyRoutine = 
		GetExortedFunctionAddress(L"PsSetCreateProcessNotifyRoutine");
	if (ulPsSetCreateProcessNotifyRoutine == 0)
	{
		return 0;
	}
	p = (PUCHAR)ulPsSetCreateProcessNotifyRoutine;
	ulSize = SizeOfProc((PVOID)ulPsSetCreateProcessNotifyRoutine);
	for (i=0;i<ulSize;i++,p++)
	{
		if (*(p-3)==0x74 &&
			*(p+5) ==0xe8)
		{
			if (MmIsAddressValidEx(p))
			{
				bFind = TRUE;
				ulAddress = *(PULONG)p;
			}
			break;
		}
	}
	if (!bFind)
	{
		return 0;
	}
	return ulAddress;
}
//
ULONG GetPspCreateThreadNotifyRoutineAddress()
{
//nt!PsSetCreateThreadNotifyRoutine+0x18:
//805d0d8e b89a0000c0      mov     eax,0C000009Ah
//805d0d93 eb2a            jmp     nt!PsSetCreateThreadNotifyRoutine+0x49 (805d0dbf)
//nt!PsSetCreateThreadNotifyRoutine+0x1f:
//805d0d95 56              push    esi
//805d0d96 be004a5680      mov     esi,offset nt!PspCreateThreadNotifyRoutine (80564a00)
//nt!PsSetCreateThreadNotifyRoutine+0x25:
//805d0d9b 6a00            push    0
//805d0d9d 53              push    ebx
//805d0d9e 56              push    esi
//805d0d9f e8a2d50300      call    nt!ExCompareExchangeCallBack (8060e346)
	ULONG ulPsSetCreateThreadNotifyRoutine;
	PUCHAR p;
	ULONG ulSize;
	ULONG i;
	ULONG ulAddress;
	BOOL bFind = FALSE;
	ulPsSetCreateThreadNotifyRoutine = 
		GetExortedFunctionAddress(L"PsSetCreateThreadNotifyRoutine");
	if (ulPsSetCreateThreadNotifyRoutine == 0)
	{
		return 0;
	}
	p = (PUCHAR)ulPsSetCreateThreadNotifyRoutine;
	ulSize = SizeOfProc((PVOID)ulPsSetCreateThreadNotifyRoutine);
	for (i=0;i<ulSize;i++,p++)
	{
		if (*(p-4)==0xeb &&
			*(p+8) ==0xe8)
		{
			if (MmIsAddressValidEx(p))
			{
				bFind = TRUE;
				ulAddress = *(PULONG)p;
			}
			break;
		}
	}
	if (!bFind)
	{
		return 0;
	}
	return ulAddress;
}
//
ULONG GetPspLoadImageNotifyRoutineAddress()
{
//805d1037 eb2a            jmp     nt!PsSetLoadImageNotifyRoutine+0x49 (805d1063)
//nt!PsSetLoadImageNotifyRoutine+0x1f:
//805d1039 56              push    esi
//805d103a bee0495680      mov     esi,offset nt!PspLoadImageNotifyRoutine (805649e0)
//nt!PsSetLoadImageNotifyRoutine+0x25:
//805d103f 6a00            push    0
//805d1041 53              push    ebx
//805d1042 56              push    esi
//805d1043 e8fed20300      call    nt!ExCompareExchangeCallBack (8060e346)
	ULONG ulPsSetLoadImageNotifyRoutine;
	PUCHAR p;
	ULONG ulSize;
	ULONG i;
	ULONG ulAddress;
	BOOL bFind = FALSE;
	ulPsSetLoadImageNotifyRoutine = 
		GetExortedFunctionAddress(L"PsSetLoadImageNotifyRoutine");
	if (ulPsSetLoadImageNotifyRoutine == 0)
	{
		return 0;
	}
	p = (PUCHAR)ulPsSetLoadImageNotifyRoutine;
	ulSize = SizeOfProc((PVOID)ulPsSetLoadImageNotifyRoutine);
	for (i=0;i<ulSize;i++,p++)
	{
		if (*(p-4)==0xeb &&
			*(p+8) ==0xe8)
		{
			if (MmIsAddressValidEx(p))
			{
				bFind = TRUE;
				ulAddress = *(PULONG)p;
			}
			break;
		}
	}
	if (!bFind)
	{
		return 0;
	}
	return ulAddress;
}
//
BOOL InitNotifyRoutineAddress()
{
	g_PspSetCreateProcessNotifyRoutine = 
		GetPspCreateProcessNotifyRoutineAddress();
	if (g_PspSetCreateProcessNotifyRoutine == 0)
	{
		return FALSE;
	}
	g_PspCreateThreadNotifyRoutine = 
		GetPspCreateThreadNotifyRoutineAddress();
	if (g_PspCreateThreadNotifyRoutine == 0)
	{
		return FALSE;
	}
	g_PspSetLoadImageNotifyRoutine = GetPspLoadImageNotifyRoutineAddress();
	if (g_PspSetLoadImageNotifyRoutine == 0)
	{
		return FALSE;
	}
	return TRUE;
}
/*睡眠指定秒的时间*/
VOID Sleep(LONG MSeconds)
{
	LARGE_INTEGER interval;
	interval.QuadPart = - 10 * 1000 * MSeconds;
	KeDelayExecutionThread(KernelMode,FALSE,&interval);
}
VOID RemoveNotifyRoutines()
{
//第一步：YYY=XXX & ~7
//第二步: *((PULONG)YYY+1) 就是函数地址了
	ULONG ulTmp;
	ULONG ulInternalAddress = 0;
	ULONG i;
	PULONG p;
	LONG uCompareOne;
	LONG uCompareTwo;
	LONG Sub;
	//Sleep(30000);//延时30s
	TpModuleBase = GetKernelModuleBase(g_MyDriverObject,"TesSafe.sys");
	if (TpModuleBase == NULL)
	{
		CodeVprint("cannot find TesSafe.sys\r\n");
		return;
	}
	p = (PULONG)g_PspSetCreateProcessNotifyRoutine;
	for (i=0;i<8;i++)
	{
		ulTmp = NOTIFY_ADDRESS_CALC_ONE(p[i]);
		if (MmIsAddressValid((PULONG)ulTmp + 1))
		{
			ulInternalAddress = *((PULONG)ulTmp + 1);
			/*判断地址是否在TP的地址空间，是的话就摘掉*/
			
			if (MmIsAddressValid(TpModuleBase))
			{
				CodeVprint("TpModuleBase:0x%x\r\n",(ULONG)TpModuleBase);
				/*如果差在某个范围内，就说明是TP设置的回调*/
				uCompareOne = (LONG)ulInternalAddress;
				uCompareTwo = (LONG)TpModuleBase;
				Sub = uCompareTwo-uCompareOne;
				if (Sub < 0x400000 && Sub > 0)
				{
					//
					PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)ulInternalAddress,TRUE);
					CodeVprint("Remove TP CreateProcessNotify\r\n");
				}
				//else
				//{
				//	CodeVprint("CreateProcess uCompareOne != uCompareTwo\r\n");
				//}
			}
		}
	}
	//////////////////////////////////////////////////////////////////////////
	p = (PULONG)g_PspCreateThreadNotifyRoutine;
	for (i=0;i<8;i++)
	{
		ulTmp = NOTIFY_ADDRESS_CALC_ONE(p[i]);
		if (MmIsAddressValid((PULONG)ulTmp + 1))
		{
			ulInternalAddress = *((PULONG)ulTmp + 1);
			/*判断地址是否在TP的地址空间，是的话就摘掉*/

			if (MmIsAddressValid(TpModuleBase))
			{
				CodeVprint("TpModuleBase:0x%x\r\n",(ULONG)TpModuleBase);
				/*如果差在某个范围内，就说明是TP设置的回调*/
				uCompareOne = (LONG)ulInternalAddress;
				uCompareTwo = (LONG)TpModuleBase;
				Sub = uCompareTwo-uCompareOne;
				if (Sub < 0x400000 && Sub > 0)
				{
					//
					PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)(ulInternalAddress));
					CodeVprint("Remove TP CreateThreadNotify\r\n");
				}
				//else
				//{
				//	CodeVprint("CreateThread uCompareOne != uCompareTwo\r\n");
				//}
			}
		}
	}
	//////////////////////////////////////////////////////////////////////////
	p = (PULONG)g_PspSetLoadImageNotifyRoutine;
	for (i=0;i<8;i++)
	{
		ulTmp = NOTIFY_ADDRESS_CALC_ONE(p[i]);
		if (MmIsAddressValid((PULONG)ulTmp + 1))
		{
			ulInternalAddress = *((PULONG)ulTmp + 1);
			/*判断地址是否在TP的地址空间，是的话就摘掉*/

			if (MmIsAddressValid(TpModuleBase))
			{
				CodeVprint("TpModuleBase:0x%x\r\n",(ULONG)TpModuleBase);
				/*如果差在某个范围内，就说明是TP设置的回调*/
				uCompareOne = (LONG)ulInternalAddress;
				uCompareTwo = (LONG)TpModuleBase;
				Sub = uCompareTwo-uCompareOne;
				if (Sub < 0x400000 && Sub > 0)
				{
					//
					PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)(ulInternalAddress));
					CodeVprint("Remove TP LoadImageNotify\r\n");
				}
				//else
				//{
				//	CodeVprint("LoadImage uCompareOne != uCompareTwo\r\n");
				//}
			}
		}
	}
}

VOID RemoveThreadProc(IN PVOID pContext)
{
	while(1)
	{
		if (bRemove)
		{
			PsTerminateSystemThread(0);
		}
		else
		{
			Sleep(5000);
			RemoveNotifyRoutines();
			CodeVprint("RemoveThread loop\r\n");
		}
	}
}
/*设置一个移除回调的系统线程*/
NTSTATUS SetDeleteNotifyThread()
{
	HANDLE hRemoveThread = NULL;
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	st = PsCreateSystemThread(&hRemoveThread,(ACCESS_MASK)THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		(PKSTART_ROUTINE)RemoveThreadProc,
		NULL);
	if (!NT_SUCCESS(st))
	{
		CodeVprint("PsCreateSystemThread failed\r\n");
		return st;
	}
	st = ObReferenceObjectByHandle(hRemoveThread,THREAD_ALL_ACCESS,*PsThreadType,KernelMode,&RemoveThread,NULL);
	if (!NT_SUCCESS(st))
	{
		ZwClose(hRemoveThread);
		hRemoveThread = NULL;
		RemoveThread = NULL;
		CodeVprint("ObReferenceObjectByHandle failed\r\n");
		return st;
	}
	ZwClose(hRemoveThread);
	ObDereferenceObject(RemoveThread);
	return st;
}

/*删除系统线程，使用bool量和PsTernaminateSystemThread*/
VOID RemoveDeleteNotifyThread()
{
	if (RemoveThread != NULL)
	{
		bRemove = TRUE;
		KeWaitForSingleObject(RemoveThread,Executive,KernelMode,TRUE,NULL);
		CodeVprint("Wait RemoveThread success!\r\n");
	}
}

/*
VOID TestEnumNotifyRoutine()
{
	PULONG p;
	ULONG ulInternalAddress;
	p = (PULONG)g_PspSetCreateProcessNotifyRoutine;
	for (i=0;i<8;i++)
	{
		ulTmp = NOTIFY_ADDRESS_CALC_ONE(p[i]);
		if (MmIsAddressValidEx((PULONG)ulTmp + 1))
		{
			ulInternalAddress = *((PULONG)ulTmp + 1);
			CodeVprint("CreateProcess:[0x%x]\r\n",ulInternalAddress);
		}
	}
	//////////////////////////////////////////////////////////////////////////
	p = (PULONG)g_PspCreateThreadNotifyRoutine;
	for (i=0;i<8;i++)
	{
		ulTmp = NOTIFY_ADDRESS_CALC_ONE(p[i]);
		if (MmIsAddressValidEx((PULONG)ulTmp + 1))
		{
			ulInternalAddress = *((PULONG)ulTmp + 1);
			CodeVprint("CreateThread:[0x%x]\r\n",ulInternalAddress);
		}
	}
	//////////////////////////////////////////////////////////////////////////
	p = (PULONG)g_PspSetLoadImageNotifyRoutine;
	for (i=0;i<8;i++)
	{
		ulTmp = NOTIFY_ADDRESS_CALC_ONE(p[i]);
		if (MmIsAddressValidEx((PULONG)ulTmp + 1))
		{
			ulInternalAddress = *((PULONG)ulTmp + 1);
			CodeVprint("LoadImage:[0x%x]\r\n",ulInternalAddress);
		}
	}
}*/