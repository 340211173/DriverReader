#include "Ntos.h"
/* ��ȡӰ�ӱ�ĵ�ַ */
PVOID GetShadowTableAddress()
{
	ULONG dwordatbyte,i;
	PUCHAR p = (PUCHAR)KeAddSystemServiceTable;
	for(i = 0; i < PAGE_SIZE; i++, p++)// ������һҳ ָ�����1 
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
			if(memcmp((PVOID)dwordatbyte, KeServiceDescriptorTable, 16) == 0)//�Ա�ǰ16�ֽ� ��ͬ���ҵ�
			{
				if((PVOID)dwordatbyte == KeServiceDescriptorTable)//�ų��Լ�
				{
					continue;
				}
				return (PVOID)dwordatbyte;
			}
		}
	}
	return FALSE;
}

/* ��reloadģ�����ҵ�ԭʼshadow ssdt�� */
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
	

	/* ���汣�����ʵ����ԭʼ��ĵ�ַ����ݱ��Ǹɾ��� */
	return pReloadShadowTable;
}
/* ��reloadģ�����ҵ�ԭʼssdt�� */
PSERVICE_DESCRIPTOR_TABLE GetOriginServiceTableFromReloadModule(ULONG OriginKernelBase,ULONG NewKernelBase)
{
	PSERVICE_DESCRIPTOR_TABLE pReloadKeServiceDescriptorTable;
	pReloadKeServiceDescriptorTable = (PSERVICE_DESCRIPTOR_TABLE)(NewKernelBase + (ULONG)KeServiceDescriptorTable - OriginKernelBase);
	pReloadKeServiceDescriptorTable->TableSize = KeServiceDescriptorTable->TableSize;
	pReloadKeServiceDescriptorTable->ServiceTable = (PULONG)(NewKernelBase + (ULONG)KeServiceDescriptorTable->ServiceTable - OriginKernelBase);
	/* ���汣�����ʵ����ԭʼ��ĵ�ַ����ݱ��Ǹɾ��� */
	return pReloadKeServiceDescriptorTable;
}
/* ��ȡ��д������openprocess����ʵ��ַ */
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
/* ��ȡһЩwin32k�ĺ�����ԭʼ��ַ */
VOID InitWin32kFunctions(PSERVICE_DESCRIPTOR_TABLE pNewShadowTable)
{
	g_RealNtUserGetMessageAddress = pNewShadowTable->ServiceTable[0x1a5];
	g_RealNtUserPeekMessageAddress = pNewShadowTable->ServiceTable[0x1da];
	//g_RealNtGdiBitBltAddress	= pNewShadowTable->ServiceTable[0xd];
	//g_RealNtGdiStretchBltAddress = pNewShadowTable->ServiceTable[0x124];
	g_RealNtUserSetWindowsHookExAddress=pNewShadowTable->ServiceTable[549];
	g_RealNtUserUnhookWindowsHookExAddress=pNewShadowTable->ServiceTable[570];
}
/* ����ntosģ�� */
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
	/* ��ʼ����д��Ҫ���ں˺��� */
	InitSsdtFunctions(ReloadServiceTable);
	g_pOriginShadowTable = (PSERVICE_DESCRIPTOR_TABLE)GetShadowTableAddress();
	/* ReloadShadowServiceTable ֻ������copyǰ7���ֽڵ����ǵĺ�����ȥ */
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
				/* ��ʼ��usermessage���������� */
				InitWin32kFunctions(ReloadShadowServiceTable);
			}
		}
	}
	//���������ں�·�������ͷŲ��Ƿ��أ�
	if (SystemKernelFilePath)
	{
		ExFreePool(SystemKernelFilePath);
	}
	//ntos�ض�λ֮��reloadģ���е�ssdt����Ļ���ԭʼ�� 

	return STATUS_SUCCESS;
}
