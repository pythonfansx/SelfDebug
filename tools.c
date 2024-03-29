#include "tools.h"

static UCHAR hexs[] = 
{
	0x0,0x1,0x2,0x3,
	0x4,0x5,0x6,0x7,
	0x8,0x9,0xA,0xB,
	0xC,0xD,0xE,0xF
};




#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)

void KernelSleep(ULONG ms, BOOLEAN alert)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= ms;
	KeDelayExecutionThread(KernelMode, alert, &my_interval);
}

UCHAR charToHex(UCHAR * ch)
{
	unsigned char temps[2] = { 0 };
	for (int i = 0; i < 2; i++)
	{
		if (ch[i] >= '0' && ch[i] <= '9')
		{
			temps[i] = (ch[i] - '0');
		}
		else if (ch[i] >= 'A' && ch[i] <= 'F')
		{
			temps[i] = (ch[i] - 'A') + 0xA;
		}
		else if (ch[i] >= 'a' && ch[i] <= 'f')
		{
			temps[i] = (ch[i] - 'a') + 0xA;
		}
	}
	return ((temps[0] << 4) & 0xf0) | (temps[1] & 0xf);
}


void initFindCodeStruct(PFindCode findCode, PCHAR code, ULONG offset/*各个结构体定位特征码的距离*/, ULONG lastAddrOffset/*特征码到目标位置的距离*/)
{

	memset(findCode, 0, sizeof(FindCode));

	findCode->lastAddressOffset = lastAddrOffset;
	findCode->offset = offset;
	
	PCHAR pTemp = code;
	int i = 0;
	for (i = 0; *pTemp != '\0'; i++)
	{
		if (*pTemp == '*' || *pTemp == '?')
		{
			findCode->code[i] = *pTemp;
			pTemp++;
			continue;
		}

		findCode->code[i] = charToHex(pTemp);
		pTemp += 2;

	}

	findCode->len = i;
}


ULONG findAddressByCode(ULONG beginAddr, ULONG endAddr,PFindCode  findCode, ULONG size)
{
	int j = 0;
	ULONG rtna = 0;

	for (int i = beginAddr; i <= endAddr; i++)
	{
		if (!MmIsAddressValid((PVOID)i))continue;
		
		//if (((ULONG)i) == 0x80588b7e + 5 && findCode[0].code[0] == 0x8B && size == 1) __asm int 3;

		for (j = 0; j < size; j++)
		{
			FindCode  fc = findCode[j];
			ULONG tempAddress = i;
			
			UCHAR * code = (UCHAR *)(tempAddress + fc.offset);
			BOOLEAN isFlags = FALSE;

			for (int k = 0; k < fc.len; k++)
			{
				if (!MmIsAddressValid((PVOID)(code+k)))
				{
					isFlags = TRUE;
					break;
				}

				if (fc.code[k] == '*' || fc.code[k] == '?') continue;

				if (code[k] != fc.code[k])
				{
					isFlags = TRUE; 
					break;
				}
			}

			if (isFlags) break;
			
		}

		//找到了
		if (j == size)
		{
			rtna = i + findCode[0].lastAddressOffset;
			break;
		}

	}

	return rtna;
}

void ProbeForWriteHandle(PHANDLE handle)
{
	*handle = *handle;
}


PKPCR __declspec(naked) GetCurrentKpcr()
{
	__asm 
	{
		mov eax, fs:[0x1c];
		ret;
	}
}

ULONG calcE8OrE9(ULONG oldAddr, ULONG newAddr)
{
	return newAddr - oldAddr - 5;
}

void insertListTail(SLIST_ENTRY * head, SLIST_ENTRY * e)
{
	while (head->Next)
	{
		head = head->Next;
	}

	head->Next = e;
}

ULONG GetFunctionAddressByCodeAddress(ULONG addr)
{
	
	ULONG nextAddr = addr + 5;
	ULONG code = *(PULONG)(addr + 1);
	//获得函数地址
	return (code + nextAddr);
}

void __declspec(naked) writeProbOff()
{
	__asm
	{
		cli;
		pushfd;
		pushad;
		mov eax, cr0;
		mov ebx, 0x10000;
		not ebx;
		and eax, ebx;
		mov cr0, eax;
		popad;
		popfd;
		sti;
		ret;
	}
}

void __declspec(naked) writeProbNo()
{
	__asm
	{
		cli;
		pushfd;
		pushad;
		mov eax, cr0;
		mov ebx, 0x10000;
		or eax, ebx;
		mov cr0, eax;
		popad;
		popfd;
		sti;
		ret;
	}
}

//void ProbeForReadSmallStructure(PVOID p, SIZE_T size, SIZE_T testSize);
