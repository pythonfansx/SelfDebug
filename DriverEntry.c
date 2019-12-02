#include "Util.h"
#include "debug.h"
#include <wdm.h>
#include "hookKifast.h"


VOID DriverUpload(PDRIVER_OBJECT pDriver)
{
	KDP("%s\r\n", __FUNCTION__);
	UnSetHookKiFastCall();
	return;
}



NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	UNREFERENCED_PARAMETER(pReg);
	NTSTATUS status = STATUS_SUCCESS;
	pDriver->DriverUnload = DriverUpload;
	
	

	initDebugVar();
	initHookKiFastGlobalVar();
	SetHookKiFastCall();

	KDP("%s\r\n",__FUNCTION__);
	return status;
}
