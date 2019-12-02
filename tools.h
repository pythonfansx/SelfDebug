#ifndef __TOOLS_H__H_
#define __TOOLS_H__H_
#include "Util.h"

typedef struct _FindCode
{
	UCHAR code[100];
	ULONG len;
	int offset;
	ULONG lastAddressOffset;
}FindCode, *PFindCode;



#define SET_BREAK_POINT __asm int 3

void KernelSleep(ULONG ms, BOOLEAN alert);


UCHAR charToHex(UCHAR * ch);

void initFindCodeStruct(PFindCode findCode,PCHAR code,ULONG offset,ULONG lastAddrOffset);
ULONG findAddressByCode(ULONG beginAddr,ULONG endAddr,PFindCode  findCode,ULONG size);

#define FindAddressByCode(PFIND_CODE,SIZE) findAddressByCode(0x80000000,0x8FFFFFFF,PFIND_CODE,SIZE)

void ProbeForWriteHandle(PHANDLE handle);
#define ProbeForReadSmallStructure(p,size,testSize) {if ( p >= MmUserProbeAddress) *(PULONG64)MmUserProbeAddress = MmUserProbeAddress;}

PKPCR  GetCurrentKpcr();


ULONG calcE8OrE9(ULONG oldAddr, ULONG newAddr);

#define  CALCJMPMACHIMECODE(XX,OO) calcE8OrE9(XX - 1,OO)


//Á´±í²Ù×÷
void insertListTail(SINGLE_LIST_ENTRY * head, SINGLE_LIST_ENTRY * e);

#define removeListElement(__HEADER__,__TYPE__,__FILED__,__DATA__,__REMOVENODE__)  \
	{																	\
		SINGLE_LIST_ENTRY * list = (__HEADER__)->Next;							\
		SINGLE_LIST_ENTRY * pre = (__HEADER__);									\
		while (list){ \
			__TYPE__ var = (__TYPE__)list;															\
			if (var->##__FILED__ == (__DATA__))							\
			{															\
				pre->Next = list->Next;									\
				*(__REMOVENODE__) = list;								\
				break;													\
			}															\
			pre = list;													\
			list = list->Next;											\
		}																\
	}



ULONG GetFunctionAddressByCodeAddress(ULONG addr);

void writeProbOff();
void writeProbNo();
#endif