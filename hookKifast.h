#ifndef __HOOK_KI_FAST_H__
#define __HOOK_KI_FAST_H__
#include <ntifs.h>



typedef struct _HookKiFastStruct
{
	ULONG oldHookAddress;
	ULONG newHookAddress;
	UCHAR code[8];
	ULONG len;
	ULONG isHookSuccess;
}HookKiFastStruct;

void initHookKiFastGlobalVar();
void interceptKiFastCall();

ULONG GetKifastCallFuncAddress();


typedef NTSTATUS(*ProcNtUnloadDriver)(__in PUNICODE_STRING DriverServiceName);

NTSTATUS NtUnloadDriver(ProcNtUnloadDriver oldFunc, __in PUNICODE_STRING DriverServiceName);


void SetHookKiFastCall();

void UnSetHookKiFastCall(); 

#endif