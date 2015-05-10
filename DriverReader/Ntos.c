#include "Ntos.h"
/* 获取影子表的地址 */
PVOID GetShadowTableAddress()
{
	ULONG dwordatbyte,i;
	PUCHAR p = (PUCHAR)KeAddSystemServiceTable;
	for(i = 0; i < PAGE_SIZE; i++, p++)// 往下找一页 指针递增1 
	{
		__try
		{
			dwordatbyte = *(PULONG)p;
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			return FALSE;
		}
		if(MmIsAddressValid((PVOID)dwordatbyte))
		{
			if(memcmp((PVOID)dwordatbyte, KeServiceDescriptorTable, 16) == 0)//对比前16字节 相同则找到
			{
				if((PVOID)dwordatbyte == KeServiceDescriptorTable)//排除自己
				{
					continue;
				}
				return (PVOID)dwordatbyte;
			}
		}
	}
	return FALSE;
}

/* 在reload模块中找到原始shadow ssdt表 */
PSERVICE_DESCRIPTOR_TABLE GetOriginShadowTableFromReloadModule(ULONG OriginKernelBase,ULONG NewKernelBase)
{
	PSERVICE_DESCRIPTOR_TABLE pOriginShadowTable;
	PSERVICE_DESCRIPTOR_TABLE pReloadShadowTable;
	pOriginShadowTable = (PSERVICE_DESCRIPTOR_TABLE)GetShadowTableAddress();
	if (!MmIsAddressValid(pOriginShadowTable))
	{
		return NULL;
	}
	pReloadShadowTable = (PSERVICE_DESCRIPTOR_TABLE)(NewKernelBase + (ULONG)pOriginShadowTable - OriginKernelBase);
	pReloadShadowTable[0].TableSize = pOriginShadowTable[0].TableSize;
	pReloadShadowTable[0].ServiceTable = (PULONG)(NewKernelBase + (ULONG)(pOriginShadowTable[0].ServiceTable) - OriginKernelBase);
	pReloadShadowTable[1].TableSize = pOriginShadowTable[1].TableSize;
	pReloadShadowTable[1].ServiceTable = (PULONG)(NewKernelBase + (ULONG)(pOriginShadowTable[1].ServiceTable) - OriginKernelBase);
	

	/* 里面保存的其实还是原始表的地址，这份表是干净的 */
	return pReloadShadowTable;
}
/* 在reload模块中找到原始ssdt表 */
PSERVICE_DESCRIPTOR_TABLE GetOriginServiceTableFromReloadModule(ULONG OriginKernelBase,ULONG NewKernelBase)
{
	PSERVICE_DESCRIPTOR_TABLE pReloadKeServiceDescriptorTable;
	pReloadKeServiceDescriptorTable = (PSERVICE_DESCRIPTOR_TABLE)(NewKernelBase + (ULONG)KeServiceDescriptorTable - OriginKernelBase);
	pReloadKeServiceDescriptorTable->TableSize = KeServiceDescriptorTable->TableSize;
	pReloadKeServiceDescriptorTable->ServiceTable = (PULONG)(NewKernelBase + (ULONG)KeServiceDescriptorTable->ServiceTable - OriginKernelBase);
	/* 里面保存的其实还是原始表的地址，这份表是干净的 */
	return pReloadKeServiceDescriptorTable;
}
/* 获取读写函数和openprocess的真实地址 */
VOID InitSsdtFunctions(PSERVICE_DESCRIPTOR_TABLE pNewTable)
{
	g_RealOpenProcessAddress = pNewTable->ServiceTable[122];
	g_RealReadMemoryAddress = pNewTable->ServiceTable[186];
	g_RealWriteMemoryAddress = pNewTable->ServiceTable[277];
	g_NtCreateThreadAddress = pNewTable->ServiceTable[53];
	g_NtDuplicateObjectAddress = pNewTable->ServiceTable[68];
	g_NtSuspendProcessAddress = pNewTable->ServiceTable[253];
	g_NtSuspendThreadAddress = pNewTable->ServiceTable[254];
}
/* 获取一些win32k的函数的原始地址 */
VOID InitWin32kFunctions(PSERVICE_DESCRIPTOR_TABLE pNewShadowTable)
{
	g_RealNtUserGetMessageAddress = pNewShadowTable->ServiceTable[0x1a5];
	g_RealNtUserPeekMessageAddress = pNewShadowTable->ServiceTable[0x1da];
	//g_RealNtGdiBitBltAddress	= pNewShadowTable->ServiceTable[0xd];
	//g_RealNtGdiStretchBltAddress = pNewShadowTable->ServiceTable[0x124];
	g_RealNtUserSetWindowsHookExAddress=pNewShadowTable->ServiceTable[549];
	g_RealNtUserUnhookWindowsHookExAddress=pNewShadowTable->ServiceTable[570];
}
/* 重载ntos模块 */
NTSTATUS ReloadNtos(PDRIVER_OBJECT   DriverObject)
{
	//PSERVICE_DESCRIPTOR_TABLE pShadowTable = NULL;
	//NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!GetNtosInformation(&SystemKernelFilePath,&SystemKernelModuleBase,&SystemKernelModuleSize))
	{
		if (SystemKernelFilePath)
		{
			ExFreePool(SystemKernelFilePath);
		}
		return STATUS_UNSUCCESSFUL;
	}
	if (!PeReload(SystemKernelFilePath,SystemKernelModuleBase,&ReloadNtosImageBase,g_MyDriverObject))
	{
		if (SystemKernelFilePath)
		{
			ExFreePool(SystemKernelFilePath);
		}
		if (ReloadNtosImageBase)
		{
			ExFreePool(ReloadNtosImageBase);
		}
		return STATUS_UNSUCCESSFUL;
	}
	ReloadServiceTable = GetOriginServiceTableFromReloadModule(SystemKernelModuleBase,(ULONG)ReloadNtosImageBase);
	/* 初始化读写需要的内核函数 */
	InitSsdtFunctions(ReloadServiceTable);
	g_pOriginShadowTable = (PSERVICE_DESCRIPTOR_TABLE)GetShadowTableAddress();
	/* ReloadShadowServiceTable 只是用来copy前7个字节到我们的函数中去 */
	//g_pOriginShadowTable =(PSERVICE_DESCRIPTOR_TABLE)ExAllocatePool(NonPagedPool,sizeof(SERVICE_DESCRIPTOR_TABLE));
	//if (g_pOriginShadowTable)
	//{
	//	RtlZeroMemory((PVOID)g_pOriginShadowTable,sizeof(SERVICE_DESCRIPTOR_TABLE));
	//	if (pShadowTable)
	//	{
	//		g_pOriginShadowTable->TableSize = pShadowTable[1].TableSize;
	//		g_pOriginShadowTable->ArgumentTable = pShadowTable[1].ArgumentTable;
	//		g_pOriginShadowTable->CounterTable = pShadowTable[1].CounterTable;
	//		g_pOriginShadowTable->ServiceTable = pShadowTable[1].ServiceTable;
	//	}
	//}
	ReloadShadowServiceTable = (PSERVICE_DESCRIPTOR_TABLE)ExAllocatePool(NonPagedPool,sizeof(SERVICE_DESCRIPTOR_TABLE));
	if (ReloadShadowServiceTable)
	{
		RtlZeroMemory(ReloadShadowServiceTable,sizeof(SERVICE_DESCRIPTOR_TABLE));

		if (g_pOriginShadowTable)
		{
			ReloadShadowServiceTable->TableSize = g_pOriginShadowTable[1].TableSize;
			ReloadShadowServiceTable->ArgumentTable = g_pOriginShadowTable[1].ArgumentTable;
			ReloadShadowServiceTable->CounterTable = g_pOriginShadowTable[1].CounterTable;
			ReloadShadowServiceTable->ServiceTable = g_pOriginShadowTable[1].ServiceTable;
			if(GetOriginalW32pTable((PVOID)ReloadWin32kImageBase,ReloadShadowServiceTable,SystemWin32kBase))
			{
				/* 初始化usermessage的两个函数 */
				InitWin32kFunctions(ReloadShadowServiceTable);
			}
		}
	}
	//这个申请的内核路径到底释放不是放呢？
	if (SystemKernelFilePath)
	{
		ExFreePool(SystemKernelFilePath);
	}
	//ntos重定位之后，reload模块中的ssdt表保存的还是原始表 

	return STATUS_SUCCESS;
}
