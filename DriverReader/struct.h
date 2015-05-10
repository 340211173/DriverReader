#ifndef _STRUCT_H_
#define _STRUCT_H_
/***************************************************************/
#include <ntddk.h>
#include <ntimage.h>// This is the include file that describes all image structures.
/***************************************************************/
#define NOP_PROC		__asm  _emit 0x90 __asm  _emit 0x90 __asm  _emit 0x90 __asm  _emit 0x90 __asm  _emit 0x90\
						__asm  _emit 0x90 __asm  _emit 0x90 __asm  _emit 0x90 __asm  _emit 0x90 __asm  _emit 0x90 
/* 根据 jmp xxxx 和call xxxx所在的那个地址，获取xxxx的值 */
#define CALL_JMP_ADDRESS(p)  ((ULONG)p + *(PULONG)((ULONG)p + 1) + 5)
__declspec(dllimport) _stdcall KeAddSystemServiceTable(PVOID, PVOID, PVOID, PVOID, PVOID);
/***************************************************************/
typedef BOOLEAN BOOL;
typedef ULONG DWORD;
typedef DWORD *PDWORD;
typedef USHORT WORD;
typedef UCHAR BYTE;
typedef BYTE *PBYTE;
typedef unsigned int UINT;
/***************************************************************/
typedef struct _AUX_ACCESS_DATA {
	PPRIVILEGE_SET PrivilegesUsed;
	GENERIC_MAPPING GenericMapping;
	ACCESS_MASK AccessesToAudit;
	ACCESS_MASK MaximumAuditMask;
	ULONG Unknown[41];
} AUX_ACCESS_DATA, *PAUX_ACCESS_DATA;

//////////////////////////////////////////////////////////////////////////
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
	PVOID EntryPointActivationContext;

	PVOID PatchInformation;

} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
/***************************************************************/
typedef struct _SERVICE_DESCRIPTOR_TABLE {
	/*
	* Table containing cServices elements of pointers to service handler
	* functions, indexed by service ID.
	*/
	PULONG   ServiceTable;
	/*
	* Table that counts how many times each service is used. This table
	* is only updated in checked builds.
	*/
	PULONG  CounterTable;
	/*
	* Number of services contained in this table.
	*/
	ULONG   TableSize;
	/*
	* Table containing the number of bytes of parameters the handler
	* function takes.
	*/
	PUCHAR  ArgumentTable;
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;
//声明系统描述表
extern PSERVICE_DESCRIPTOR_TABLE    KeServiceDescriptorTable;
//////////////////////////////////////////////////////////////////////////
typedef struct _OBJECT_TYPE_INITIALIZER {
	USHORT Length;
	BOOLEAN UseDefaultObject;
	BOOLEAN CaseInsensitive;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	BOOLEAN MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	PVOID DumpProcedure;
	PVOID OpenProcedure;
	PVOID CloseProcedure;
	PVOID DeleteProcedure;
	PVOID ParseProcedure;
	PVOID SecurityProcedure;
	PVOID QueryNameProcedure;
	PVOID OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;
//////////////////////////////////////////////////////////////////////////
typedef struct _OBJECT_TYPE_INITIALIZER_7600                                                                                                                             // 25 elements, 0x50 bytes (sizeof)
{
	/*0x000*/     UINT16       Length;
	union                                                                                                                                                           // 2 elements, 0x1 bytes (sizeof)
	{
		/*0x002*/         UINT8        ObjectTypeFlags;
		struct                                                                                                                                                      // 7 elements, 0x1 bytes (sizeof)
		{
			/*0x002*/             UINT8        CaseInsensitive : 1;                                                                                                                       // 0 BitPosition
			/*0x002*/             UINT8        UnnamedObjectsOnly : 1;                                                                                                                    // 1 BitPosition
			/*0x002*/             UINT8        UseDefaultObject : 1;                                                                                                                      // 2 BitPosition
			/*0x002*/             UINT8        SecurityRequired : 1;                                                                                                                      // 3 BitPosition
			/*0x002*/             UINT8        MaintainHandleCount : 1;                                                                                                                   // 4 BitPosition
			/*0x002*/             UINT8        MaintainTypeList : 1;                                                                                                                      // 5 BitPosition
			/*0x002*/             UINT8        SupportsObjectCallbacks : 1;                                                                                                               // 6 BitPosition
		};
	};
	/*0x004*/     ULONG32      ObjectTypeCode;
	/*0x008*/     ULONG32      InvalidAttributes;
	/*0x00C*/     struct _GENERIC_MAPPING GenericMapping;                                                                                                                         // 4 elements, 0x10 bytes (sizeof)
	/*0x01C*/     ULONG32      ValidAccessMask;
	/*0x020*/     ULONG32      RetainAccess;
	/*0x024*/     enum _POOL_TYPE PoolType;
	/*0x028*/     ULONG32      DefaultPagedPoolCharge;
	/*0x02C*/     ULONG32      DefaultNonPagedPoolCharge;
	/*0x030*/     PVOID DumpProcedure;
	/*0x034*/     PVOID OpenProcedure;
	/*0x038*/     PVOID CloseProcedure;
	/*0x03C*/     PVOID DeleteProcedure;
	/*0x040*/     PVOID ParseProcedure;
	/*0x044*/     PVOID SecurityProcedure;
	/*0x048*/     PVOID QueryNameProcedure;
	/*0x04C*/     PVOID OkayToCloseProcedure;
}OBJECT_TYPE_INITIALIZER_7600, *POBJECT_TYPE_INITIALIZER_7600;


//定义系统信息类
typedef struct _SYSTEM_MODULE_INFORMATION //系统模块信息
{
	ULONG  Reserved[2];  
	ULONG  Base;        
	ULONG  Size;         
	ULONG  Flags;        
	USHORT Index;       
	USHORT Unknown;     
	USHORT LoadCount;   
	USHORT ModuleNameOffset;
	CHAR   ImageName[256];   
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _tagSysModuleList { //模块链表结构
	ULONG ulCount;
	SYSTEM_MODULE_INFORMATION smi[1];
} MODULES, *PMODULES;


#define SystemHandleInformation 16
typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectTypesInformation,
	ObjectHandleFlagInformation,
	ObjectSessionInformation,
	MaxObjectInfoClass  // MaxObjectInfoClass should always be the last enum
} OBJECT_INFORMATION_CLASS;

typedef enum _OBJECT_INFO_CLASS {
	ObjectBasicInfo,
	ObjectNameInfo,
	ObjectTypeInfo,
	ObjectAllTypesInfo,
	ObjectProtectionInfo
} OBJECT_INFO_CLASS;

// SystemHandleInformation
typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG       ProcessId;
	UCHAR       ObjectTypeNumber;
	UCHAR       Flags;
	USHORT      Handle;
	PVOID       Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _HANDLE_INFO {       // Information about open handles
	union {
		PEPROCESS   Process;        // Pointer to PEPROCESS owning the Handle
		ULONG       Count;          // Count of HANDLE_INFO structures following this structure
	} HandleInfo;
	USHORT          HandleCount;
} HANDLE_INFO, *PHANDLE_INFO;

typedef struct _HANDLE_TABLE_ENTRY_INFO {
	ULONG AuditMask;
} HANDLE_TABLE_ENTRY_INFO, *PHANDLE_TABLE_ENTRY_INFO;

typedef struct _HANDLE_TABLE_ENTRY {
	union {
		PVOID                       Object;
		ULONG                       ObAttributes;
		PHANDLE_TABLE_ENTRY_INFO    InfoTable;
		ULONG                       Value;
	};
	union {
		ULONG                       GrantedAccess;
		USHORT                      GrantedAccessIndex;
		LONG                        NextFreeTableEntry;
	};
	USHORT                          CreatorBackTraceIndex;
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;
/*
 使用之前请先调用InitializeCommonVariables初始化全局变量
*/

typedef struct _HANDLE_TABLE {
	
    //
    //  A set of flags used to denote the state or attributes of this
    //  particular handle table
    //
	
    ULONG Flags;
	
    //
    //  The number of handle table entries in use.
    //
	
    LONG HandleCount;
	
    //
    //  A pointer to the top level handle table tree node.
    //
	
    PHANDLE_TABLE_ENTRY **Table;
	
    //
    //  The process who is being charged quota for this handle table and a
    //  unique process id to use in our callbacks
    //
	
    struct _EPROCESS *QuotaProcess;
    HANDLE UniqueProcessId;
	
    //
    //  This is a singly linked list of free table entries.  We don't actually
    //  use pointers, but have each store the index of the next free entry
    //  in the list.  The list is managed as a lifo list.  We also keep track
    //  of the next index that we have to allocate pool to hold.
    //
	
    LONG FirstFreeTableEntry;
    LONG NextIndexNeedingPool;
	
    //
    //  This is the lock used to protect the fields in the record, and the
    //  handle table tree in general.  Individual handle table entries that are
    //  not free have their own lock
    //
	
    ERESOURCE HandleTableLock;
	
    //
    //  The list of global handle tables.  This field is protected by a global
    //  lock.
    //
	
    LIST_ENTRY HandleTableList;
	
    //
    //  The following field is used to loosely synchronize thread contention
    //  on a handle.  If a thread wants to wait for a handle to be unlocked
    //  it will wait on this event with a short timeout.  Any handle unlock
    //  operation will pulse this event if there are threads waiting on it
    //
	
    KEVENT HandleContentionEvent;
} HANDLE_TABLE, *PHANDLE_TABLE;	

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_INFORMATION Information[];
}SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;
//

typedef struct _KREQUEST_PACKET {
	PVOID CurrentPacket[3];
	PKIPI_WORKER WorkerRoutine;
} KREQUEST_PACKET, *PKREQUEST_PACKET;

typedef struct _KAPC_STATE             // 5 elements, 0x18 bytes (sizeof) 
{                                                                         
	/*0x000*/     struct _LIST_ENTRY ApcListHead[2];                                    
	/*0x010*/     PVOID   Process;                                            
	/*0x014*/     UINT8        KernelApcInProgress;                                     
	/*0x015*/     UINT8        KernelApcPending;                                        
	/*0x016*/     UINT8        UserApcPending;                                                                               
}KAPC_STATE, *PKAPC_STATE;                                                

#endif