#ifndef _INLINEHOOK_H_
#define _INLINEHOOK_H_
#include "struct.h"

BOOLEAN HookFunctionByHeaderAddress(DWORD NewFunctionAddress,
	DWORD oldFunctionAddress,
	PVOID HookZone,
	int *patchCodeLen,
	PVOID *lpRet);

VOID UnHookFunctionByHeaderAddress(DWORD oldFunctionAddress,PVOID HookZone, int patchCodeLen);

#endif

