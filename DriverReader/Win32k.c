#include "Win32k.h"
/* NtUserGetMessage  索引号 0x1a5 */
/* NtUserPeekMessage 索引号 0x1da */
/* NtGdiBitBlt		 索引号 0xd */
/* NtGdiStretchBlt	 索引号 0x124 */

BOOL GetOriginalW32pTable(PVOID ImageBase,PSERVICE_DESCRIPTOR_TABLE W32pTable,DWORD Win32kBase)
{
        BOOL bRet=FALSE;
        PIMAGE_NT_HEADERS NtHeaders;
        ULONG_PTR EntryPoint;
        NtHeaders = RtlImageNtHeader(ImageBase);
        if (NtHeaders)
        {
                DWORD dwEntryPoint;
                DWORD dwCurAddress;
				DWORD Length=0;
				PUCHAR pOpcode;
                EntryPoint = NtHeaders->OptionalHeader.AddressOfEntryPoint;
                EntryPoint += (ULONG_PTR)ImageBase;
                dwEntryPoint=(DWORD)EntryPoint;
                /*IDA反汇编结果：
                68 80 A2 99 BF          push    offset off_BF99A280
                FF 15 58 D4 98 BF       call    ds:KeAddSystemServiceTable
                */
                //通过call    ds:KeAddSystemServiceTable的定位，该定位应该比较准确
                for(dwCurAddress = dwEntryPoint; dwCurAddress < dwEntryPoint + 0x1000; dwCurAddress+=Length)
                {
						Length = SizeOfCode((PUCHAR)dwCurAddress, &pOpcode);
                        if(*(WORD *)dwCurAddress == 0x15ff )
                        {  
                                //计算出加载后的ds:KeAddSystemServiceTable地址，然后该地址中存放的即是KeAddSystemServiceTable真实入口地址
                                DWORD dwFunAddress = *(PDWORD)(*(PDWORD)(dwCurAddress + 2)-Win32kBase+(DWORD)ImageBase);
                                if((DWORD)KeAddSystemServiceTable == dwFunAddress)
                                {
                                        //将该地址结合内核中Win32k的加载地址进行重定位
                                        W32pTable->ServiceTable =(PDWORD) (*(PDWORD)(dwCurAddress - 4) - Win32kBase + (DWORD)ImageBase);
                                        bRet=TRUE;
                                        break;
                                }
                        }
                }
        }
        return bRet;
}

/* 重载win32k的模块*/
NTSTATUS ReloadWin32k(PDRIVER_OBJECT   DriverObject)
{
	SystemWin32kBase = (ULONG)GetKernelModuleBase(DriverObject,"win32k.sys");
	if (!PeReload(L"\\SystemRoot\\System32\\win32k.sys",
		SystemWin32kBase,&ReloadWin32kImageBase,g_MyDriverObject))
	{
		if (ReloadWin32kImageBase)
		{
			ExFreePool(ReloadWin32kImageBase);
		}
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}