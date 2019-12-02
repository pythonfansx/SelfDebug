#pragma once
#include <ntifs.h>
#pragma warning(disable:4214 4201 4133 4100 4127)

#ifdef DBG
	#define KDP(__XX__,__YY__) DbgPrint("[Self debug]:"##__XX__,__YY__)
	#define KDP0(__XX__) DbgPrint("[Self debug]:"##__XX__)
#else
	#define KDP(__XX__,__YY__)
	#define KDP0(__XX__)
#endif