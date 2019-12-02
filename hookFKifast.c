#include "hookKifast.h"
#include "tools.h"
#include "debug.h"


HookKiFastStruct hkf = {0};
ULONG KifastCallFuncAddress = 0;
ULONG KifastCallFuncRetAddress = 0;
ULONG KifastFilterRetAddress = 0;
ULONG interceptKiFastCallRetOffsetAddress= 0;
extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;


void initHookKiFastGlobalVar()
{
	KifastCallFuncAddress = GetKifastCallFuncAddress();
	KifastCallFuncRetAddress = KifastCallFuncAddress + 0x102;
	KifastFilterRetAddress = KifastCallFuncAddress + 0xFC;

	hkf.oldHookAddress = KifastCallFuncAddress + 0xf6;
	hkf.newHookAddress = (ULONG)interceptKiFastCall;
	hkf.len = 8;
}
ULONG RetFunc[] =
{
	(ULONG)NtCreateDebugObject,
	(ULONG)NtDebugActiveProcess,
	(ULONG)NtRemoveProcessDebug,
};

ULONG __stdcall FilterFunc(ULONG funcAddress)
{
	ULONG * base = (ULONG *)KeServiceDescriptorTable->Base;
	
	ULONG HookFunc[] =
	{
		base[0x21],
		base[0x39],
		base[0xBF],
	};
	 
	int index = -1;

	for (int i = 0; i < sizeof(HookFunc) / sizeof(ULONG); i++)
	{
		if (HookFunc[i] == funcAddress)
		{
			index = i;
			break;
		}
	}
	
	return index != -1 ? RetFunc[index] : 0;
}


void __declspec(naked) interceptKiFastCall()
{
	__asm
	{
	
		jnb __ExceptionHandler;
		//cmp eax,0x39;
		//jnz __GOTOCALL;
		//int 3;

__GOTOCALL:
		
		pushfd;
		pushad;
		push ebx;
		call FilterFunc;
		mov [esp + 0x1c], eax;
		popad;
		popfd;
		cmp eax, 0;
		jz __oldCallFunc2;
		
		mov ebx, eax;
		// rep movsd;
		//push ebx;
		//call eax;
		jmp KifastFilterRetAddress;
		//jmp __endl;

__oldCallFunc2:
		//rep movsd;
		//call ebx;
		jmp KifastFilterRetAddress;
		
__endl:
		mov esp, ebp;
		jmp KifastCallFuncRetAddress;

__ExceptionHandler:
		test    byte ptr[ebp + 0x6c], 1;
		jz      __GOTOCALL;
		mov     eax, 0C0000005h;
		jmp     __endl;
	}
}




ULONG __declspec(naked) GetKifastCallFuncAddress()
{
	__asm
	{
		mov ecx, 0x176;
		rdmsr;
		ret;
	}
}

void SetHookKiFastCall()
{
	
	memcpy(hkf.code, (PVOID)hkf.oldHookAddress, hkf.len);
	UCHAR code[8] = { 0xe9 };
	ULONG address = hkf.newHookAddress - hkf.oldHookAddress - 5;
	*(ULONG*)(code + 1) = address;
	code[5] = 0x90;

	memcpy(code + 6, (PVOID)(hkf.oldHookAddress + 6), 2);
	writeProbOff();
	//__asm int 3;
	__asm
	{
		cli;
	
		mov esi, [hkf];
		mov ecx, dword ptr ss : [code + 4];
		mov ebx, dword ptr ss : [code];

		mov eax, [hkf + 0x8];
		mov edx, [hkf + 0xc];


		lock cmpxchg8b qword ptr ss : [esi];

		cmp[esi], 0xe9
		jnz __exit;
		mov eax, 1;
		mov[hkf + 0x14], eax;
	__exit:
		sti;
	}
	writeProbNo();

}

void UnSetHookKiFastCall()
{

	if (hkf.isHookSuccess)
	{
		UCHAR code[8] = {0};
		memcpy(code, (PVOID)hkf.oldHookAddress, 8);
		writeProbOff();
		__asm
		{
			//int 3;
			cli;
			mov esi, [hkf];
			mov ecx, dword ptr ss : [hkf + 0xc];
			mov ebx, dword ptr ss : [hkf + 0x8];

			mov eax, dword ptr ss : [code];
			mov edx, dword ptr ss : [code + 0x4];

			lock cmpxchg8b qword ptr ss : [esi];
			mov ebx, [esi];
			cmp ebx, [hkf + 0x8];

			jnz __exit;
			mov eax, 0;
			mov[hkf + 0x14], eax;
		__exit:
			sti;
		}

		writeProbNo();
	}

}


PUNICODE_STRING GetDriverServiceName()
{
	UNICODE_STRING  driverServiceName;

	PUNICODE_STRING  MydriverServiceName = (PUNICODE_STRING)ExAllocatePoolWithQuota(PagedPool, sizeof(UNICODE_STRING));
	RtlZeroMemory(MydriverServiceName,sizeof(UNICODE_STRING));
	PWCHAR buffer = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\createDebug";

	MydriverServiceName->Buffer = (PWCHAR)ExAllocatePoolWithQuota(PagedPool, wcslen(buffer) * 2);
	RtlZeroMemory(MydriverServiceName->Buffer, wcslen(buffer) * 2);
	MydriverServiceName->MaximumLength = wcslen(buffer) * 2;

	RtlInitUnicodeString(&driverServiceName, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\createDebug");
	RtlCopyUnicodeString(MydriverServiceName, &driverServiceName);
	return MydriverServiceName;
}

VOID __declspec(naked) UnloadDriverContext(IN PVOID StartContext)
{
	__asm
	{
		
		call GetDriverServiceName;
		push eax;
		push 0;
		push 10000;
		call KernelSleep;
		pop eax;
		push eax;
		push ZwUnloadDriver;
		push 0;
		push 0;
		push 0;
		push GENERIC_ALL;
		push esp;
		call PsCreateSystemThread;
		ret 4; 
	}
}

NTSTATUS NtUnloadDriver(ProcNtUnloadDriver oldFunc, __in PUNICODE_STRING DriverServiceName)
{
	KPROCESSOR_MODE requestorMode = KeGetPreviousMode();
	PUNICODE_STRING driverServiceName = NULL;;
	UNICODE_STRING MydriverServiceName;
	RtlInitUnicodeString(&MydriverServiceName, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\createDebug");
	PWCHAR nameBuffer = NULL;
	
	if (requestorMode != KernelMode)
	{
		ProbeForRead(DriverServiceName->Buffer, DriverServiceName->Length, 1);
		nameBuffer = (PWCHAR)ExAllocatePoolWithQuota(PagedPool,
			DriverServiceName->Length);
		driverServiceName = (PUNICODE_STRING)ExAllocatePoolWithQuota(PagedPool,
			sizeof(UNICODE_STRING));
		RtlCopyMemory(nameBuffer,
			DriverServiceName->Buffer,
			DriverServiceName->Length);
		RtlInitUnicodeString(driverServiceName, nameBuffer);
		
	}
	else
	{
		driverServiceName = DriverServiceName;
	}
	//__asm int 3;
	KdPrint(("п╤ть%wZ\r\n", driverServiceName));
	BOOLEAN isEquals = !RtlCompareUnicodeString(driverServiceName, &MydriverServiceName, FALSE);
	if (isEquals)
	{
		UnSetHookKiFastCall();
		KdPrint(("ур╣╫%wZ\r\n", driverServiceName));
		
	}

	if (requestorMode != KernelMode)
	{
		ExFreePool(nameBuffer);
		ExFreePool(driverServiceName);
	}

	if (isEquals)
	{
		HANDLE hThread;
		NTSTATUS status = PsCreateSystemThread(&hThread, GENERIC_ALL, NULL, NULL, NULL, UnloadDriverContext, NULL);
		if (status == STATUS_SUCCESS)
		{
			ZwClose(hThread);
		}
		
		return status;
	}
	
	return oldFunc(DriverServiceName);
	
}
