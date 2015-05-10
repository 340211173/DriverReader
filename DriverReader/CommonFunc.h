#ifndef _COMMONFUNC_H_
#define _COMMONFUNC_H_
#include "struct.h"
#include "WindowsVersion.h"

//#define _DBG_
#ifdef _DBG_
#define CodeVprint  DbgPrint
#else
#define CodeVprint
#endif

typedef struct _MMPTE_SOFTWARE {
	ULONG Valid : 1;
	ULONG PageFileLow : 4;
	ULONG Protection : 5;
	ULONG Prototype : 1;
	ULONG Transition : 1;
	ULONG PageFileHigh : 20;
} MMPTE_SOFTWARE;

typedef struct _MMPTE_TRANSITION {
	ULONG Valid : 1;
	ULONG Write : 1;
	ULONG Owner : 1;
	ULONG WriteThrough : 1;
	ULONG CacheDisable : 1;
	ULONG Protection : 5;
	ULONG Prototype : 1;
	ULONG Transition : 1;
	ULONG PageFrameNumber : 20;
} MMPTE_TRANSITION;

typedef struct _MMPTE_PROTOTYPE {
	ULONG Valid : 1;
	ULONG ProtoAddressLow : 7;
	ULONG ReadOnly : 1;  // if set allow read only access.
	ULONG WhichPool : 1;
	ULONG Prototype : 1;
	ULONG ProtoAddressHigh : 21;
} MMPTE_PROTOTYPE;

typedef struct _MMPTE_HARDWARE {
	ULONG Valid : 1;
	ULONG Write : 1;       // UP version
	ULONG Owner : 1;
	ULONG WriteThrough : 1;
	ULONG CacheDisable : 1;
	ULONG Accessed : 1;
	ULONG Dirty : 1;
	ULONG LargePage : 1;
	ULONG Global : 1;
	ULONG CopyOnWrite : 1; // software field
	ULONG Prototype : 1;   // software field
	ULONG reserved : 1;    // software field
	ULONG PageFrameNumber : 20;
} MMPTE_HARDWARE, *PMMPTE_HARDWARE;

typedef struct _MMPTE {
	union  {
		ULONG Long;
		MMPTE_HARDWARE Hard;
		MMPTE_PROTOTYPE Proto;
		MMPTE_SOFTWARE Soft;
		MMPTE_TRANSITION Trans;
	} u;
} MMPTE, *PMMPTE;

typedef struct _MMPTE_SOFTWARE_PAE {
	ULONGLONG Valid : 1;
	ULONGLONG PageFileLow : 4;
	ULONGLONG Protection : 5;
	ULONGLONG Prototype : 1;
	ULONGLONG Transition : 1;
	ULONGLONG Unused : 20;
	ULONGLONG PageFileHigh : 32;
} MMPTE_SOFTWARE_PAE;

typedef struct _MMPTE_TRANSITION_PAE {
	ULONGLONG Valid : 1;
	ULONGLONG Write : 1;
	ULONGLONG Owner : 1;
	ULONGLONG WriteThrough : 1;
	ULONGLONG CacheDisable : 1;
	ULONGLONG Protection : 5;
	ULONGLONG Prototype : 1;
	ULONGLONG Transition : 1;
	ULONGLONG PageFrameNumber : 24;
	ULONGLONG Unused : 28;
} MMPTE_TRANSITION_PAE;

typedef struct _MMPTE_PROTOTYPE_PAE {
	ULONGLONG Valid : 1;
	ULONGLONG Unused0: 7;
	ULONGLONG ReadOnly : 1;  // if set allow read only access.  LWFIX: remove
	ULONGLONG Unused1: 1;
	ULONGLONG Prototype : 1;
	ULONGLONG Protection : 5;
	ULONGLONG Unused: 16;
	ULONGLONG ProtoAddress: 32;
} MMPTE_PROTOTYPE_PAE;

typedef struct _MMPTE_HARDWARE_PAE {
	ULONGLONG Valid : 1;
	ULONGLONG Write : 1;        // UP version
	ULONGLONG Owner : 1;
	ULONGLONG WriteThrough : 1;
	ULONGLONG CacheDisable : 1;
	ULONGLONG Accessed : 1;
	ULONGLONG Dirty : 1;
	ULONGLONG LargePage : 1;
	ULONGLONG Global : 1;
	ULONGLONG CopyOnWrite : 1; // software field
	ULONGLONG Prototype : 1;   // software field
	ULONGLONG reserved0 : 1;  // software field
	ULONGLONG PageFrameNumber : 24;
	ULONGLONG reserved1 : 28;  // software field
} MMPTE_HARDWARE_PAE, *PMMPTE_HARDWARE_PAE;

typedef struct _MMPTE_PAE {
	union  {
		LARGE_INTEGER Long;
		MMPTE_HARDWARE_PAE Hard;
		MMPTE_PROTOTYPE_PAE Proto;
		MMPTE_SOFTWARE_PAE Soft;
		MMPTE_TRANSITION_PAE Trans;
	} u;
} MMPTE_PAE;

typedef MMPTE_PAE *PMMPTE_PAE;

#define PTE_BASE    0xC0000000
#define PDE_BASE    0xC0300000
#define PDE_BASE_PAE 0xc0600000

#define MiGetPdeAddress(va)  ((MMPTE*)(((((ULONG)(va)) >> 22) << 2) + PDE_BASE))
#define MiGetPteAddress(va) ((MMPTE*)(((((ULONG)(va)) >> 12) << 2) + PTE_BASE))

#define MiGetPdeAddressPae(va)   ((PMMPTE_PAE)(PDE_BASE_PAE + ((((ULONG)(va)) >> 21) << 3)))
#define MiGetPteAddressPae(va)   ((PMMPTE_PAE)(PTE_BASE + ((((ULONG)(va)) >> 12) << 3)))

#define MM_ZERO_PTE 0
#define MM_ZERO_KERNEL_PTE 0


#define MM_ZERO_ACCESS         0  // this value is not used.
#define MM_READONLY            1
#define MM_EXECUTE             2
#define MM_EXECUTE_READ        3
#define MM_READWRITE           4  // bit 2 is set if this is writable.
#define MM_WRITECOPY           5
#define MM_EXECUTE_READWRITE   6
#define MM_EXECUTE_WRITECOPY   7
#define MM_NOCACHE             8
#define PAE_ON (1<<5)
typedef enum VALIDITY_CHECK_STATUS{
	VCS_INVALID,
	VCS_VALID,
	VCS_TRANSITION,
	VCS_PAGEDOUT,
	VCS_DEMANDZERO,
	VCS_PROTOTYPE
}VALIDITY_CHECK_STATUS;
//声明内核函数使用
NTKERNELAPI VOID KeSetSystemAffinityThread (KAFFINITY Affinity);  
NTKERNELAPI VOID KeRevertToUserAffinityThread (VOID);
NTKERNELAPI
	NTSTATUS
	SeCreateAccessState(
	PACCESS_STATE AccessState,
	PAUX_ACCESS_DATA AuxData,
	ACCESS_MASK DesiredAccess,
	PGENERIC_MAPPING GenericMapping
	);

NTKERNELAPI
	VOID
	SeDeleteAccessState(
	PACCESS_STATE AccessState
	);
NTKERNELAPI				
	NTSTATUS
	ObCreateObject(
	IN KPROCESSOR_MODE ProbeMode,
	IN POBJECT_TYPE ObjectType,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN KPROCESSOR_MODE OwnershipMode,
	IN OUT PVOID ParseContext OPTIONAL,
	IN ULONG ObjectBodySize,
	IN ULONG PagedPoolCharge,
	IN ULONG NonPagedPoolCharge,
	OUT PVOID *Object
	);
NTKERNELAPI                                                     
	NTSTATUS                                                        
	ObReferenceObjectByHandle(                                      
	IN HANDLE Handle,                                           
	IN ACCESS_MASK DesiredAccess,                               
	IN POBJECT_TYPE ObjectType OPTIONAL,                        
	IN KPROCESSOR_MODE AccessMode,                              
	OUT PVOID *Object,                                          
	OUT POBJECT_HANDLE_INFORMATION HandleInformation OPTIONAL   
	);                                                          
NTKERNELAPI                                                     
	NTSTATUS                                                        
	ObOpenObjectByPointer(                                          
	IN PVOID Object,                                            
	IN ULONG HandleAttributes,                                  
	IN PACCESS_STATE PassedAccessState OPTIONAL,                
	IN ACCESS_MASK DesiredAccess OPTIONAL,                      
	IN POBJECT_TYPE ObjectType OPTIONAL,                        
	IN KPROCESSOR_MODE AccessMode,                              
	OUT PHANDLE Handle                                          
	); 
NTSTATUS __stdcall  ZwQuerySystemInformation(
	__in       ULONG SystemInformationClass,
	__inout    PVOID SystemInformation,
	__in       ULONG SystemInformationLength,
	__out_opt  PULONG ReturnLength
	);
NTKERNELAPI
	VOID
	KeAttachProcess (
	PEPROCESS Process
	);

NTKERNELAPI
	VOID
	KeDetachProcess (
	VOID
	);
//////////////////////////////////////////////////////////////////////////
NTSTATUS SafeCopyMemory(PVOID SrcAddr, PVOID DstAddr, ULONG Size);
//
BOOL MmIsAddressValidEx(
	IN PVOID Pointer
	);
VOID WPOFF();
VOID WPON();
PCHAR PsGetProcessImageFileName(PEPROCESS eprocess);
BOOL IsFromGameProcess();
BOOL IsOurProcess(PEPROCESS process);
ULONG GetExortedFunctionAddress(PWCHAR FunctionName);
ULONG GetOriginKiFastCallEntryAddress();
PVOID GetKernelModuleInfo(CHAR *DriverName);
NTSTATUS LookupProcessByName(
	IN PCHAR pcProcessName,
	OUT PEPROCESS *pEprocess
	);
NTSTATUS GetPspCidTable(PHANDLE_TABLE *pPspHandleAddr);
extern char *OwnName;
VOID Delay(ULONG uSeconds);
#endif