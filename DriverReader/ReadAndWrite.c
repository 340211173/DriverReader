/***************************************************************************************
* AUTHOR : vLink
* DATE   : 2014-9-13
* MODULE : ReadAndWrite.C
* 
* Command: 
*	Source of IOCTRL Sample Driver
*
* Description:
*		Demonstrates communications between USER and KERNEL.
*
****************************************************************************************
* Copyright (C) 2010 vLink.
****************************************************************************************/

//#######################################################################################
//# I N C L U D E S
//#######################################################################################
#include "ReadAndWrite.h"
/*
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
	((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
	)*/
#define START CTL_CODE(FILE_DEVICE_UNKNOWN,0x8a1,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define STOP CTL_CODE(FILE_DEVICE_UNKNOWN,0x8a2,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define REMOVE_NOTIFY CTL_CODE(FILE_DEVICE_UNKNOWN,0x8a3,METHOD_BUFFERED,FILE_ANY_ACCESS)
//////////////////////Global Variables////////////////////////////////////
extern BYTE* ReloadNtosImageBase;
extern BYTE*  ReloadWin32kImageBase;
extern PSERVICE_DESCRIPTOR_TABLE ReloadShadowServiceTable;

BOOL bWin7 = FALSE;
//BOOL bMessage = FALSE;
//BOOL bSetHookEx = FALSE;
BOOL bKiFastCall = FALSE;
BOOL bObj = FALSE;
PDRIVER_OBJECT 	g_MyDriverObject;//自身驱动的基址
PVOID g_MyDriverBase;
ULONG g_MyDriverSize;//自身驱动的大小
//
/**/
NTSTATUS RemoveNotifyStatus = STATUS_UNSUCCESSFUL;
BOOL bIsInitReplaceFunc = FALSE;
//////////////////////////////////////////////////////////////////////////
VOID
DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{	
	PDEVICE_OBJECT pDevObject = pDriverObj->DeviceObject;
	UNICODE_STRING SymLinkName;
	//if (ReloadShadowServiceTable)
	//{
	//	ExFreePool(ReloadShadowServiceTable);
	//}
	//__asm int 3;

	if (ReloadNtosImageBase)
	{
		//ExFreePool(ReloadNtosImageBase);
	}
	if (ReloadWin32kImageBase)
	{
		//这里都不能卸载了！！！我晕
		ExFreePool(ReloadWin32kImageBase);
		ReloadWin32kImageBase = NULL;
	}
	RtlInitUnicodeString(&SymLinkName,L"\\??\\HelloDDK");
	IoDeleteSymbolicLink(&SymLinkName);
	IoDeleteDevice(pDevObject);
	CodeVprint("Delete Device and SymLinkName success!\r\n");
	return;
}


/* 创建设备对象 */
NTSTATUS CreateDevice(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS       st = STATUS_SUCCESS;
	UNICODE_STRING DeviceName;
	UNICODE_STRING SymLinkName;
	PDEVICE_OBJECT pDeviceObject;
	RtlInitUnicodeString(&DeviceName, L"\\Device\\HelloDDKDevice");
	st=IoCreateDevice(
		pDriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		TRUE,
		&pDeviceObject);
	if (!NT_SUCCESS(st))
	{
		CodeVprint("CreateDevice failed!\r\n");
		return st;
	}
	pDeviceObject->Flags|=DO_BUFFERED_IO;
	CodeVprint("CreateDevice success!\r\n");
	RtlInitUnicodeString(&SymLinkName,L"\\??\\HelloDDK");
	st=IoCreateSymbolicLink(&SymLinkName,&DeviceName);
	if (!NT_SUCCESS(st))
	{
		IoDeleteDevice(pDeviceObject);
		CodeVprint("CreateSymLinkName failed!\r\n");
		return st;
	}
	CodeVprint("CreateSymLinkName success!\r\n");
	return st;
}
/* 通用IRP分发 */
NTSTATUS IoDispatch(PDEVICE_OBJECT pDeviceObject,PIRP pIrp)
{
	pIrp->IoStatus.Status=STATUS_SUCCESS;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
/* 与应用层通信IRP */
NTSTATUS IoHelloDDKDispatch(PDEVICE_OBJECT pDeviceObject,PIRP pIrp)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	switch(code)
	{
	case START:
		{
						CodeVprint("Start irp\r\n");
			//RemoveNotifyStatus = SetDeleteNotifyThread();
			//bSetHookEx = HookNtUserSetWindowsHookEx();
			//bMessage = HookUserMessage();
			//FuckKiSwapThread();
			/*驱动断链*/
			//HideDriver(g_MyDriverObject);
			if (bIsInitReplaceFunc)
			{
				HideProcess(PsGetCurrentProcess());
			}
			bObj = HookObReferenceObjectByHandle();
			bKiFastCall = HookNewKiFastCallEntry();

		}
		break;
	case STOP:
		{
			//DbgBreakPoint();
			CodeVprint("Stop irp\r\n");
			//if (bSetHookEx)
			//{
			//	UnhookNtUserSetWindowsHookEx();
			//}
			//if (bMessage)
			//{
			//	UnhookUserMessage();
			//}
			if(bKiFastCall)
			{
				UnHookNewKiFastCallEntry();
			}
			if (bObj)
			{
				UnhookObReferenceObjectByHandle();
			}
			//恢复进程路径
			if (bIsInitReplaceFunc)
			{
				ResumeProcess();
			}
			//RecoverPspTable();
			//UnFuckKiSwapThread();
/* 			if (RemoveNotifyStatus == STATUS_SUCCESS)
			{
				RemoveDeleteNotifyThread();
			} */
		}
		break;
	case REMOVE_NOTIFY:
		{
			CodeVprint("RemoveNotify irp\r\n");
			RemoveNotifyRoutines();
		}
		break;
	}
	pIrp->IoStatus.Status=STATUS_SUCCESS;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
/****************************************************************************************/
//				          D R I V E R   E N T R Y   P O I N T	
/****************************************************************************************/
NTSTATUS
DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	CreateDevice(pDriverObj);
	pDriverObj->DriverUnload = DriverUnload;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE]          = IoDispatch;
	pDriverObj->MajorFunction[IRP_MJ_CREATE]         = IoDispatch;
	pDriverObj->MajorFunction[IRP_MJ_WRITE]          = IoDispatch;
	pDriverObj->MajorFunction[IRP_MJ_READ]           = IoDispatch;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoHelloDDKDispatch;
	//记录自身驱动的信息
	g_MyDriverObject = pDriverObj;
	g_MyDriverBase = pDriverObj->DriverStart;
	g_MyDriverSize = pDriverObj->DriverSize;
	//Initialize Windows Version
	GetWindowsVersion();
	if (WinVersion == WINDOWS_VERSION_7_7000 ||
		WinVersion == WINDOWS_VERSION_7_7600_UP)
	{
		bWin7 = TRUE;
	}
	else if (WinVersion == WINDOWS_VERSION_XP)
	{
		bWin7 = FALSE;
	}
	else
	{
		//既不是win7也不是winxp
		goto DriverRet;
	}
	//测试
	//__asm int 3;
	status = ReloadWin32k(g_MyDriverObject);
	if (status != STATUS_SUCCESS)
	{
		goto DriverRet;
	}
	status = ReloadNtos(g_MyDriverObject);
	if (status != STATUS_SUCCESS)
	{
		goto DriverRet;
	}
	if (!InitNotifyRoutineAddress())
	{
		status = STATUS_UNSUCCESSFUL;
		goto DriverRet;
	}
	//__asm int 3;
	bIsInitReplaceFunc = InitReplaceFunctions();

DriverRet:
	return status;
}

