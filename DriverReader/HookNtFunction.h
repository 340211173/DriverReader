#ifndef _HOOKKIFASTCALLENTRY_H_
#define _HOOKKIFASTCALLENTRY_H_
#include "struct.h"
#include "InlineHook.h"
#include "Ntos.h"
#include "WindowsVersion.h"
#include "CommonFunc.h"

#define PROCESS_VM_READ 0x0010


#define PASSIVE_LEVEL 0             // Passive release level
#define LOW_LEVEL 0                 // Lowest interrupt level
#define APC_LEVEL 1                 // APC interrupt level
#define DISPATCH_LEVEL 2            // Dispatcher level

#define PROFILE_LEVEL 27            // timer used for profiling.
#define CLOCK1_LEVEL 28             // Interval clock 1 level - Not used on x86
#define CLOCK2_LEVEL 28             // Interval clock 2 level
#define IPI_LEVEL 29                // Interprocessor interrupt level
#define POWER_LEVEL 30              // Power failure level
#define HIGH_LEVEL 31               // Highest interrupt level

// end_ntddk end_wdm end_ntosp

// synchronization level - UP system
#define SYNCH_LEVEL DISPATCH_LEVEL  

// synchronization level - MP system
#define SYNCH_LEVEL (IPI_LEVEL-2)   // ntddk wdm ntosp

#define KiSynchIrql SYNCH_LEVEL     // enable portable code


extern BYTE*  ReloadWin32kImageBase;
extern ULONG SystemWin32kBase;
extern BYTE* ReloadNtosImageBase;
extern ULONG SystemKernelModuleBase;
extern PSERVICE_DESCRIPTOR_TABLE g_pOriginShadowTable;
//
extern ULONG g_RealReadMemoryAddress;
extern ULONG g_RealWriteMemoryAddress;
extern ULONG g_RealOpenProcessAddress;
extern ULONG g_NtCreateThreadAddress;
extern ULONG g_NtDuplicateObjectAddress;
extern ULONG g_NtSuspendProcessAddress;
extern ULONG g_NtSuspendThreadAddress;

extern ULONG g_RealNtUserGetMessageAddress;
extern ULONG g_RealNtUserPeekMessageAddress;

extern ULONG g_RealNtGdiBitBltAddress;
extern ULONG g_RealNtGdiStretchBltAddress;

extern ULONG g_RealNtUserSetWindowsHookExAddress;//=pNewShadowTable->ServiceTable[549];
extern ULONG g_RealNtUserUnhookWindowsHookExAddress;//=pNewShadowTable->ServiceTable[570];
//
extern PEPROCESS g_pProtectProcess;
extern ULONG g_nProtectId;

typedef NTSTATUS (__stdcall *KEWAITFORSINGGEOBJECT) (
	__in PVOID Object,
	__in KWAIT_REASON WaitReason,
	__in KPROCESSOR_MODE WaitMode,
	__in BOOLEAN Alertable,
	__in_opt PLARGE_INTEGER Timeout
	);
KEWAITFORSINGGEOBJECT ReloadKeWaitForSingleObject;

typedef NTSTATUS (__stdcall *NTOPENPROCESS) (
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	);
NTOPENPROCESS ReloadNtOpenProcess;

typedef NTSTATUS (__stdcall *NTREADVIRTUALMEMORY)(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__out_bcount(BufferSize) PVOID Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesRead
	);
NTREADVIRTUALMEMORY ReloadNtReadVirtualMemory;

typedef NTSTATUS (__stdcall *NTWRITEVIRTUALMEMORY) (
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__in_bcount(BufferSize) CONST VOID *Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesWritten
	);
NTWRITEVIRTUALMEMORY ReloadNtWriteVirtualMemory;

typedef NTSTATUS (__stdcall *NTCREATETHREAD)(
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in HANDLE ProcessHandle,
	__out PCLIENT_ID ClientId,
	__in PCONTEXT ThreadContext,
	__in PVOID InitialTeb,
	__in BOOL CreateSuspended
	);
NTCREATETHREAD ReloadNtCreateThread;

typedef NTSTATUS (__stdcall *NTDUPLICATEOBJECT) (
	__in HANDLE SourceProcessHandle,
	__in HANDLE SourceHandle,
	__in_opt HANDLE TargetProcessHandle,
	__out_opt PHANDLE TargetHandle,
	__in ACCESS_MASK DesiredAccess,
	__in ULONG HandleAttributes,
	__in ULONG Options
	);
NTDUPLICATEOBJECT ReloadNtDuplicateobject;


typedef NTSTATUS (__stdcall *NTSUSPENDPROCESS)(
	__in HANDLE ProcessHandle
	);
NTSUSPENDPROCESS ReloadNtSuspendProcess;

typedef NTSTATUS (__stdcall *NTSUSPENDTHREAD)(
	__in HANDLE ThreadHandle,
	__out_opt PULONG PreviousSuspendCount
	);
NTSUSPENDTHREAD ReloadNtSuspendThread;

typedef NTSTATUS
	(__stdcall *OBREFERENCEOBJECTBYHANDLE) (
	__in HANDLE Handle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__out PVOID *Object,
	__out_opt POBJECT_HANDLE_INFORMATION HandleInformation
	);

//#define ObjectNameInformation 1

typedef BOOL (__stdcall *NTUSERGETMESSAGE)(PVOID pMsg,
	INT hWnd,
	UINT MsgFilterMin,
	UINT MsgFilterMax);
NTUSERGETMESSAGE ReloadNtUserGetMessage;
//
typedef BOOL (__stdcall *NTUSERPEEKMESSAGE)( PVOID pMsg,
	INT hWnd,
	UINT MsgFilterMin,
	UINT MsgFilterMax,
	UINT RemoveMsg);
NTUSERPEEKMESSAGE ReloadNtUserPeekMessage;
typedef PVOID (__stdcall *NTUSHERSETWINDOWSHOOKEX)(
	ULONG Mod, 
	PUNICODE_STRING ModuleName, 
	DWORD ThreadId, 
	int HookId, 
	PVOID HookProc, 
	DWORD dwFlags);
//NTUSHERSETWINDOWSHOOKEX ReloadNtUserSetWindowsHookEx;

typedef ULONG  (__stdcall *KEIPIGENERICCALL) (
	IN PKIPI_BROADCAST_WORKER BroadcastFunction,
	IN ULONG_PTR Context
	);
typedef BOOLEAN (*EX_ENUMERATE_HANDLE_ROUTINE)(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
	);
typedef BOOLEAN (*__ExEnumHandleTable)(
	IN PHANDLE_TABLE HandleTable,
	IN EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
	IN PVOID EnumParameter,
	OUT PHANDLE Handle OPTIONAL
	);
NTSYSAPI
	NTSTATUS
	NTAPI
	ZwDuplicateObject (
	__in HANDLE SourceProcessHandle,
	__in HANDLE SourceHandle,
	__in_opt HANDLE TargetProcessHandle,
	__out_opt PHANDLE TargetHandle,
	__in ACCESS_MASK DesiredAccess,
	__in ULONG HandleAttributes,
	__in ULONG Options
	);

NTSYSAPI
	NTSTATUS
	NTAPI
	ZwQueryObject (
	__in HANDLE Handle,
	__in OBJECT_INFORMATION_CLASS ObjectInformationClass,
	__out_bcount_opt(ObjectInformationLength) PVOID ObjectInformation,
	__in ULONG ObjectInformationLength,
	__out_opt PULONG ReturnLength
	);

NTKERNELAPI
	PEPROCESS
	IoThreadToProcess(
	IN PETHREAD Thread
	);

//
NTSTATUS PsLookupProcessByProcessId(
	HANDLE ProcessId,
	PEPROCESS *Process
	);
BOOLEAN IsFromGameProcess();
ULONG GetExortedFunctionAddress(PWCHAR FunctionName);


BOOL HookObReferenceObjectByHandle();
VOID UnhookObReferenceObjectByHandle();

//
BOOL HookUserMessage();
VOID UnhookUserMessage();
///*  */
//BOOL HookGdiBlt();
//VOID UnhookGdiBlt();
BOOL HookNewKiFastCallEntry();
VOID UnHookNewKiFastCallEntry();
BOOL HookNtUserSetWindowsHookEx();
VOID UnhookNtUserSetWindowsHookEx();
//BOOL FuckKiSwapThread();
//VOID UnFuckKiSwapThread();
#endif