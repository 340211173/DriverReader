#include "Win32k.h"
/* NtUserGetMessage  ������ 0x1a5 */
/* NtUserPeekMessage ������ 0x1da */
/* NtGdiBitBlt		 ������ 0xd */
/* NtGdiStretchBlt	 ������ 0x124 */

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
                /*IDA���������
                68 80 A2 99 BF          push    offset off_BF99A280
                FF 15 58 D4 98 BF       call    ds:KeAddSystemServiceTable
                */
                //ͨ��call    ds:KeAddSystemServiceTable�Ķ�λ���ö�λӦ�ñȽ�׼ȷ
                for(dwCurAddress = dwEntryPoint; dwCurAddress < dwEntryPoint + 0x1000; dwCurAddress+=Length)
                {
						Length = SizeOfCode((PUCHAR)dwCurAddress, &pOpcode);
                        if(*(WORD *)dwCurAddress == 0x15ff )
                        {  
                                //��������غ��ds:KeAddSystemServiceTable��ַ��Ȼ��õ�ַ�д�ŵļ���KeAddSystemServiceTable��ʵ��ڵ�ַ
                                DWORD dwFunAddress = *(PDWORD)(*(PDWORD)(dwCurAddress + 2)-Win32kBase+(DWORD)ImageBase);
                                if((DWORD)KeAddSystemServiceTable == dwFunAddress)
                                {
                                        //���õ�ַ����ں���Win32k�ļ��ص�ַ�����ض�λ
                                        W32pTable->ServiceTable =(PDWORD) (*(PDWORD)(dwCurAddress - 4) - Win32kBase + (DWORD)ImageBase);
                                        bRet=TRUE;
                                        break;
                                }
                        }
                }
        }
        return bRet;
}

/* ����win32k��ģ��*/
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