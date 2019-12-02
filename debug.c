#include "debug.h"
#include "tools.h"
#include "struct.h"
#include <ntimage.h>


POBJECT_TYPE DbgkDebugObjectType = NULL;

FAST_MUTEX DbgkpProcessDebugPortMutex;
PsGetNextProcessThreadProc PsGetNextProcessThread = NULL;
MmGetFileNameForAddressProc MmGetFileNameForAddress = NULL;

//KeAcquireQueuedSpinLockRaiseToSynchProc KeAcquireQueuedSpinLockRaiseToSynch = NULL;;
KiWaitTestProc KiWaitTest = NULL;;
KiUnlockDispatcherDatabaseProc KiUnlockDispatcherDatabase = NULL;

KeAcquireQueuedSpinLockAtDpcLevelProc KeAcquireQueuedSpinLockAtDpcLevel = NULL;
KeReleaseQueuedSpinLockFromDpcLevelProc KeReleaseQueuedSpinLockFromDpcLevel = NULL;
KiInsertQueueApcProc KiInsertQueueApc = NULL;

BOOLEAN initDebugVar()
{
	//初始化锁
	
	ExInitializeFastMutex(&DbgkpProcessDebugPortMutex);
	BOOLEAN isSuccess = FALSE;
	do
	{
		FindCode findCodes[3] = { 0 };
		if (DbgkDebugObjectType == NULL)
		{
			initFindCodeStruct(&findCodes[0], "e9****8d45*5053536a*53ff75*ff75*ff35****ff75*e8****3bc30f*****8b45*33f6468970*8958*8958*c6***c6", 0, 0x16);
			
			DbgkDebugObjectType = (POBJECT_TYPE) (*(PULONG)(*(PULONG)(FindAddressByCode(findCodes, 1))));
			KDP("DbgkDebugObjectType %x\r\n", DbgkDebugObjectType);
			if (DbgkDebugObjectType == NULL)
			{
				break;
			}
		}

		if (PsGetNextProcessThread == NULL)
		{
			initFindCodeStruct(&findCodes[0], "FF8B****8D77*8B0E83E1*8D51*8BC1F00FB1163BC10F85****8B45*85C074*8BB8", 0, -0x14);
			PsGetNextProcessThread = (PsGetNextProcessThreadProc)FindAddressByCode(findCodes, 1);
			KDP("PsGetNextProcessThread %x\r\n", PsGetNextProcessThread);
			if (PsGetNextProcessThread == NULL)
			{
				break;
			}
		}

		if (MmGetFileNameForAddress == NULL)
		{
			initFindCodeStruct(&findCodes[0], "8B4D*E8****85C075*BF****EB*8B50*B9****23D13BD174*8B40*85C074", 0, -0x20);
			MmGetFileNameForAddress = (POBJECT_TYPE)FindAddressByCode(findCodes, 1);
			KDP("MmGetFileNameForAddress %x\r\n", MmGetFileNameForAddress);
			if (MmGetFileNameForAddress == NULL)
			{
				break;
			}
		}

		if (KiWaitTest == NULL)
		{
			initFindCodeStruct(&findCodes[0], "33C9FF15****8B4D*8845*8D81****8A100FBEF285F674*FECA881075*80B9", 0, -7);
			ULONG func = FindAddressByCode(findCodes, 1);
			if (func == 0)
			{
				break;
			}

			//KeAcquireQueuedSpinLockRaiseToSynch = (KeAcquireQueuedSpinLockRaiseToSynchProc)(*(PULONG)(*(PULONG)(func + 0xb)));
			KiWaitTest = (KiInsertQueueApcProc)GetFunctionAddressByCodeAddress(func + 0x41);
			KiUnlockDispatcherDatabase = (KiUnlockDispatcherDatabaseProc)GetFunctionAddressByCodeAddress(func + 0x49);
			KDP("KiWaitTest %x\r\n", KiWaitTest);
			KDP("KiUnlockDispatcherDatabase %x\r\n", KiUnlockDispatcherDatabase);
		}

		if (KeAcquireQueuedSpinLockAtDpcLevel == NULL)
		{
			initFindCodeStruct(&findCodes[0], "8D8E****8D55*FF15****64A1****8D88****E8****0FBEBE****83FF*8B1D****0F84****80BE*****75", 0, -0xE);
			ULONG func = FindAddressByCode(findCodes, 1);
			if (func == 0)
			{
				break;
			}

			KeAcquireQueuedSpinLockAtDpcLevel = (KeAcquireQueuedSpinLockAtDpcLevelProc)GetFunctionAddressByCodeAddress(func + 0x29);
			KiInsertQueueApc = (KiWaitTestProc)GetFunctionAddressByCodeAddress(func + 0x68);
			KeReleaseQueuedSpinLockFromDpcLevel = (KeReleaseQueuedSpinLockFromDpcLevelProc)GetFunctionAddressByCodeAddress(func + 0x81);
			KDP("KeAcquireQueuedSpinLockAtDpcLevel %x\r\n", KeAcquireQueuedSpinLockAtDpcLevel);
			KDP("KiInsertQueueApc %x\r\n", KiInsertQueueApc);
			KDP("KeReleaseQueuedSpinLockFromDpcLevel %x\r\n", KeReleaseQueuedSpinLockFromDpcLevel);

		}

		//DbgBreakPoint();
		isSuccess = TRUE;

	} while (0);

	
	return isSuccess;
}

int ExSystemExceptionFilter(VOID)
{
	return(ExGetPreviousMode() != KernelMode ? EXCEPTION_EXECUTE_HANDLER: EXCEPTION_CONTINUE_SEARCH);
}


NTSTATUS NtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
	)
{

	
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE Handle;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject =	NULL;

	PAGED_CODE();

	//
	// Get previous processor mode and probe output arguments if necessary.
	// Zero the handle for error paths.
	//

	PreviousMode = KeGetPreviousMode();

	try {
		if (PreviousMode != KernelMode) {
			ProbeForWriteHandle(DebugObjectHandle);
		}
		*DebugObjectHandle = NULL;

	} except(ExSystemExceptionFilter()) { // If previous mode is kernel then don't handle the exception
		return GetExceptionCode();
	}

	if (Flags & ~DEBUG_KILL_ON_CLOSE) {
		return STATUS_INVALID_PARAMETER;
	}

	//
	// Create a new debug object and initialize it.
	//
	//查找特征码
	Status = ObCreateObject(PreviousMode,
		DbgkDebugObjectType,
		ObjectAttributes,
		PreviousMode,
		NULL,
		sizeof(DEBUG_OBJECT),
		0,
		0,
		&DebugObject);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	ExInitializeFastMutex(&DebugObject->Mutex);
	InitializeListHead(&DebugObject->EventList);
	KeInitializeEvent(&DebugObject->EventsPresent, NotificationEvent, FALSE);

	if (Flags & DEBUG_KILL_ON_CLOSE) {
		DebugObject->Flags = DEBUG_OBJECT_KILL_ON_CLOSE;
	}
	else {
		DebugObject->Flags = 0;
	}

	//
	// Insert the object into the handle table
	//
	Status = ObInsertObject(DebugObject,
		NULL,
		DesiredAccess,
		0,
		NULL,
		&Handle);


	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	try {
		*DebugObjectHandle = Handle;
	} except(ExSystemExceptionFilter()) {
		//
		// The caller changed the page protection or deleted the memory for the handle.
		// No point closing the handle as process rundown will do that and we don't know its still the same handle
		//
		Status = GetExceptionCode();
	}

	return Status;
	
}

NTSTATUS NtDebugActiveProcess(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle
	)
{
	NTSTATUS Status;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject;
	PMyEPROCESS Process;
	PETHREAD LastThread;

	PAGED_CODE();

	PreviousMode = KeGetPreviousMode();

	Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_SET_PORT,
		*PsProcessType,
		PreviousMode,
		&Process,
		NULL);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	//
	// Don't let us debug ourselves or the system process.
	//
	if (Process == (PMyEPROCESS)PsGetCurrentProcess() || Process == (PMyEPROCESS)PsInitialSystemProcess) {
		ObDereferenceObject(Process);
		return STATUS_ACCESS_DENIED;
	}


	Status = ObReferenceObjectByHandle(DebugObjectHandle,
		DEBUG_PROCESS_ASSIGN,
		DbgkDebugObjectType,
		PreviousMode,
		&DebugObject,
		NULL);

	if (NT_SUCCESS(Status)) {
		//
		// We will be touching process address space. Block process rundown.
		//
		if (ExAcquireRundownProtection(&Process->RundownProtect)) {

			//
			// Post the fake process create messages etc.
			//
			Status = DbgkpPostFakeProcessCreateMessages(Process,
				DebugObject,
				&LastThread);

			//
			// Set the debug port. If this fails it will remove any faked messages.
			//
			Status = DbgkpSetProcessDebugObject(Process,
				DebugObject,
				Status,
				LastThread);

			ExReleaseRundownProtection(&Process->RundownProtect);
		}
		else {
			Status = STATUS_PROCESS_IS_TERMINATING;
		}

		ObDereferenceObject(DebugObject);
	}
	ObDereferenceObject(Process);

	return Status;
}

NTSTATUS DbgkpPostFakeProcessCreateMessages(
	IN PMyEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD *pLastThread
	)
{
	NTSTATUS Status;
	KAPC_STATE ApcState;
	PETHREAD Thread;
	PETHREAD LastThread;

	PAGED_CODE();

	//
	// Attach to the process so we can touch its address space
	//
	KeStackAttachProcess(&Process->Pcb, &ApcState);

	Status = DbgkpPostFakeThreadMessages(Process,
		DebugObject,
		NULL,
		&Thread,
		&LastThread);

	if (NT_SUCCESS(Status)) {
		Status = DbgkpPostFakeModuleMessages(Process, Thread, DebugObject);
		if (!NT_SUCCESS(Status)) {
			ObDereferenceObject(LastThread);
			LastThread = NULL;
		}
		ObDereferenceObject(Thread);
	}
	else {
		LastThread = NULL;
	}

	KeUnstackDetachProcess(&ApcState);

	*pLastThread = LastThread;

	return Status;
}

NTSTATUS DbgkpSetProcessDebugObject(
	IN PMyEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PMyETHREAD LastThread
)
{
	NTSTATUS Status;
	PMyETHREAD ThisThread;
	LIST_ENTRY TempList;
	PLIST_ENTRY Entry;
	PDEBUG_EVENT DebugEvent;
	BOOLEAN First;
	PMyETHREAD Thread;
	BOOLEAN GlobalHeld;
	PMyETHREAD FirstThread;

	PAGED_CODE();

	ThisThread = PsGetCurrentThread();

	InitializeListHead(&TempList);

	First = TRUE;
	GlobalHeld = FALSE;

	if (!NT_SUCCESS(MsgStatus)) {
		LastThread = NULL;
		Status = MsgStatus;
	}
	else {
		Status = STATUS_SUCCESS;
	}

	//
	// Pick up any threads we missed
	//
	if (NT_SUCCESS(Status)) {

		while (1) {
			//
			// Acquire the debug port mutex so we know that any new threads will
			// have to wait to behind us.
			//
			GlobalHeld = TRUE;

			ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);

			//
			// If the port has been set then exit now.
			//
			if (Process->DebugPort != NULL) {
				Status = STATUS_PORT_ALREADY_SET;
				break;
			}
			//
			// Assign the debug port to the process to pick up any new threads
			//
			Process->DebugPort = DebugObject;

			//
			// Reference the last thread so we can deref outside the lock
			//
			ObReferenceObject(LastThread);

			//
			// Search forward for new threads
			//
			Thread = PsGetNextProcessThread(Process, LastThread);
			if (Thread != NULL) {

				//
				// Remove the debug port from the process as we are
				// about to drop the lock
				//
				Process->DebugPort = NULL;

				ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);

				GlobalHeld = FALSE;

				ObDereferenceObject(LastThread);

				//
				// Queue any new thread messages and repeat.
				//

				Status = DbgkpPostFakeThreadMessages(Process,
					DebugObject,
					Thread,
					&FirstThread,
					&LastThread);
				if (!NT_SUCCESS(Status)) {
					LastThread = NULL;
					break;
				}
				ObDereferenceObject(FirstThread);
			}
			else {
				break;
			}
		}
	}

	//
	// Lock the debug object so we can check its deleted status
	//
	ExAcquireFastMutex(&DebugObject->Mutex);

	//
	// We must not propagate a debug port thats got no handles left.
	//

	if (NT_SUCCESS(Status)) {
		if ((DebugObject->Flags&DEBUG_OBJECT_DELETE_PENDING) == 0) {
			PS_SET_BITS(&Process->Flags, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT | PS_PROCESS_FLAGS_CREATE_REPORTED);
			ObReferenceObject(DebugObject);
		}
		else {
			Process->DebugPort = NULL;
			Status = STATUS_DEBUGGER_INACTIVE;
		}
	}

	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		) {

		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		Entry = Entry->Flink;

		if ((DebugEvent->Flags&DEBUG_EVENT_INACTIVE) != 0 && DebugEvent->BackoutThread == ThisThread) {
			Thread = DebugEvent->Thread;

			//
			// If the thread has not been inserted by CreateThread yet then don't
			// create a handle. We skip system threads here also
			//
			if (NT_SUCCESS(Status) && Thread->GrantedAccess != 0 && !IS_SYSTEM_THREAD(Thread)) {
				//
				// If we could not acquire rundown protection on this
				// thread then we need to suppress its exit message.
				//
				if ((DebugEvent->Flags&DEBUG_EVENT_PROTECT_FAILED) != 0) {
					PS_SET_BITS(&Thread->CrossThreadFlags,
						PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG);
					RemoveEntryList(&DebugEvent->EventList);
					InsertTailList(&TempList, &DebugEvent->EventList);
				}
				else {
					if (First) {
						DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
						KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
						First = FALSE;
					}
					DebugEvent->BackoutThread = NULL;
					PS_SET_BITS(&Thread->CrossThreadFlags,
						PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);

				}
			}
			else {
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}

			if (DebugEvent->Flags&DEBUG_EVENT_RELEASE) {
				DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;
				ExReleaseRundownProtection(&Thread->RundownProtect);
			}

		}
	}

	ExReleaseFastMutex(&DebugObject->Mutex);

	if (GlobalHeld) {
		ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);
	}

	if (LastThread != NULL) {
		ObDereferenceObject(LastThread);
	}

	while (!IsListEmpty(&TempList)) {
		Entry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		DbgkpWakeTarget(DebugEvent);
	}

	if (NT_SUCCESS(Status)) {
		DbgkpMarkProcessPeb(Process);
	}

	return Status;
}

NTSTATUS DbgkpPostFakeModuleMessages(
	IN PMyEPROCESS Process,
	IN PMyETHREAD Thread,
	IN PDEBUG_OBJECT DebugObject)
{
	PMyPEB Peb = (PMyPEB)Process->Peb;
	PPEB_LDR_DATA Ldr;
	PLIST_ENTRY LdrHead, LdrNext;
	PLDR_DATA_TABLE_ENTRY LdrEntry;
	DBGKM_APIMSG ApiMsg;
	ULONG i;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING Name;
	PIMAGE_NT_HEADERS NtHeaders;
	NTSTATUS Status;
	IO_STATUS_BLOCK iosb;

	PAGED_CODE();

	if (Peb == NULL) {
		return STATUS_SUCCESS;
	}

	try {
		Ldr = Peb->Ldr;

		LdrHead = &Ldr->InLoadOrderModuleList;

	

		ProbeForReadSmallStructure(LdrHead, sizeof(LIST_ENTRY), sizeof(UCHAR));
		for (LdrNext = LdrHead->Flink, i = 0;
			LdrNext != LdrHead && i < 500;
			LdrNext = LdrNext->Flink, i++) {

			//
			// First image got send with process create message
			//
			if (i > 0) {
				RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));

				LdrEntry = CONTAINING_RECORD(LdrNext, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				ProbeForReadSmallStructure(LdrEntry, sizeof(LDR_DATA_TABLE_ENTRY), sizeof(UCHAR));

				ApiMsg.ApiNumber = DbgKmLoadDllApi;
				ApiMsg.u.LoadDll.BaseOfDll = LdrEntry->DllBase;
				ApiMsg.u.LoadDll.NamePointer = NULL;

				ProbeForReadSmallStructure(ApiMsg.u.LoadDll.BaseOfDll, sizeof(IMAGE_DOS_HEADER), sizeof(UCHAR));

				NtHeaders = RtlImageNtHeader(ApiMsg.u.LoadDll.BaseOfDll);
				if (NtHeaders) {
					ApiMsg.u.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg.u.LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
				
				Status = MmGetFileNameForAddress(NtHeaders, &Name);
				if (NT_SUCCESS(Status)) {
					InitializeObjectAttributes(&oa,
						&Name,
						OBJ_FORCE_ACCESS_CHECK | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
						NULL,
						NULL);

					Status = ZwOpenFile(&ApiMsg.u.LoadDll.FileHandle,
						GENERIC_READ | SYNCHRONIZE,
						&oa,
						&iosb,
						FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
						FILE_SYNCHRONOUS_IO_NONALERT);
					if (!NT_SUCCESS(Status)) {
						ApiMsg.u.LoadDll.FileHandle = NULL;
					}
					ExFreePool(Name.Buffer);
				}
				Status = DbgkpQueueMessage(Process,
					Thread,
					&ApiMsg,
					DEBUG_EVENT_NOWAIT,
					DebugObject);
				if (!NT_SUCCESS(Status) && ApiMsg.u.LoadDll.FileHandle != NULL) {
					ObCloseHandle(ApiMsg.u.LoadDll.FileHandle, KernelMode);
				}

			}
			ProbeForReadSmallStructure(LdrNext, sizeof(LIST_ENTRY), sizeof(UCHAR));
		}
	} except(EXCEPTION_EXECUTE_HANDLER) {

	}

	return STATUS_SUCCESS;
}

VOID PsQuitNextProcessThread(IN PETHREAD Thread)
{
	ObDereferenceObject(Thread);
}

NTSTATUS DbgkpPostFakeThreadMessages(
	IN PMyEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PMyETHREAD StartThread,
	OUT PMyETHREAD *pFirstThread,
	OUT PMyETHREAD *pLastThread
	)
{
	NTSTATUS Status;
	PMyETHREAD Thread, FirstThread, LastThread;
	DBGKM_APIMSG ApiMsg;
	BOOLEAN First = TRUE;
	BOOLEAN IsFirstThread;
	PIMAGE_NT_HEADERS NtHeaders;
	ULONG Flags;
	NTSTATUS Status1;

	PAGED_CODE();

	LastThread = FirstThread = NULL;

	Status = STATUS_UNSUCCESSFUL;

	if (StartThread != NULL) {
		First = FALSE;
		FirstThread = StartThread;
		ObReferenceObject(FirstThread);
	}
	else {
		StartThread = PsGetNextProcessThread(Process, NULL);
		First = TRUE;
	}

	for (Thread = StartThread;
		Thread != NULL;
		Thread = PsGetNextProcessThread(Process, Thread)) {

		Flags = DEBUG_EVENT_NOWAIT;

		//
		// Keep a track ont he last thread we have seen.
		// We use this as a starting point for new threads after we
		// really attach so we can pick up any new threads.
		//
		if (LastThread != NULL) {
			ObDereferenceObject(LastThread);
		}
		LastThread = Thread;
		ObReferenceObject(LastThread);

		//
		// Acquire rundown protection of the thread.
		// This stops the thread exiting so we know it can't send
		// it's termination message
		//
		if (ExAcquireRundownProtection(&Thread->RundownProtect)) {
			Flags |= DEBUG_EVENT_RELEASE;

			//
			// Suspend the thread if we can for the debugger
			// We don't suspend terminating threads as we will not be giving details
			// of these to the debugger.
			//

			if (!IS_SYSTEM_THREAD(Thread)) {
				Status1 = PsSuspendThread(Thread, NULL);
				if (NT_SUCCESS(Status1)) {
					Flags |= DEBUG_EVENT_SUSPEND;
				}
			}
		}
		else {
			//
			// Rundown protection failed for this thread.
			// This means the thread is exiting. We will mark this thread
			// later so it doesn't sent a thread termination message.
			// We can't do this now because this attach might fail.
			//
			Flags |= DEBUG_EVENT_PROTECT_FAILED;
		}

		RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));

		if (First && (Flags&DEBUG_EVENT_PROTECT_FAILED) == 0 &&
			!IS_SYSTEM_THREAD(Thread) && Thread->GrantedAccess != 0) {
			IsFirstThread = TRUE;
		}
		else {
			IsFirstThread = FALSE;
		}

		if (IsFirstThread) {
			ApiMsg.ApiNumber = DbgKmCreateProcessApi;
			if (Process->SectionObject != NULL) { // system process doesn't have one of these!
				ApiMsg.u.CreateProcessInfo.FileHandle = DbgkpSectionToFileHandle(Process->SectionObject);
			}
			else {
				ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
			}
			ApiMsg.u.CreateProcessInfo.BaseOfImage = Process->SectionBaseAddress;
			try {
				NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);
				if (NtHeaders) {
					ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL; // Filling this in breaks MSDEV!
					//                        (PVOID)(NtHeaders->OptionalHeader.ImageBase + NtHeaders->OptionalHeader.AddressOfEntryPoint);
					ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg.u.CreateProcessInfo.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
			} except(EXCEPTION_EXECUTE_HANDLER) {
				ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL;
				ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = 0;
				ApiMsg.u.CreateProcessInfo.DebugInfoSize = 0;
			}
		}
		else {
			ApiMsg.ApiNumber = DbgKmCreateThreadApi;
			ApiMsg.u.CreateThread.StartAddress = Thread->StartAddress;
		}
		Status = DbgkpQueueMessage(Process,
			Thread,
			&ApiMsg,
			Flags,
			DebugObject);
		if (!NT_SUCCESS(Status)) {
			if (Flags&DEBUG_EVENT_SUSPEND) {
				PsResumeThread(Thread, NULL);
			}
			if (Flags&DEBUG_EVENT_RELEASE) {
				ExReleaseRundownProtection(&Thread->RundownProtect);
			}
			if (ApiMsg.ApiNumber == DbgKmCreateProcessApi && ApiMsg.u.CreateProcessInfo.FileHandle != NULL) {
				ObCloseHandle(ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
			}
			PsQuitNextProcessThread(Thread);
			break;
		}
		else if (IsFirstThread) {
			First = FALSE;
			ObReferenceObject(Thread);
			FirstThread = Thread;
		}
	}


	if (!NT_SUCCESS(Status)) {
		if (FirstThread) {
			ObDereferenceObject(FirstThread);
		}
		if (LastThread != NULL) {
			ObDereferenceObject(LastThread);
		}
	}
	else {
		if (FirstThread) {
			*pFirstThread = FirstThread;
			*pLastThread = LastThread;
		}
		else {
			Status = STATUS_UNSUCCESSFUL;
		}
	}
	return Status;
}




NTSTATUS DbgkpQueueMessage(
	IN PMyEPROCESS Process,
	IN PMyETHREAD Thread,
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject
)
{
	PDEBUG_EVENT DebugEvent;
	DEBUG_EVENT StaticDebugEvent;
	PDEBUG_OBJECT DebugObject;
	NTSTATUS Status;

	PAGED_CODE();

	if (Flags&DEBUG_EVENT_NOWAIT) {
		DebugEvent = ExAllocatePoolWithQuotaTag(NonPagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE,
			sizeof(*DebugEvent),
			'EgbD');
		if (DebugEvent == NULL) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		DebugEvent->Flags = Flags | DEBUG_EVENT_INACTIVE;
		ObReferenceObject(Process);
		ObReferenceObject(Thread);
		DebugEvent->BackoutThread = PsGetCurrentThread();
		DebugObject = TargetDebugObject;
	}
	else {
		DebugEvent = &StaticDebugEvent;
		DebugEvent->Flags = Flags;

		ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);

		DebugObject = Process->DebugPort;

		//
		// See if this create message has already been sent.
		//
		if (ApiMsg->ApiNumber == DbgKmCreateThreadApi ||
			ApiMsg->ApiNumber == DbgKmCreateProcessApi) {
			if (Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG) {
				DebugObject = NULL;
			}
		}

		//
		// See if this exit message is for a thread that never had a create
		//
		if (ApiMsg->ApiNumber == DbgKmExitThreadApi ||
			ApiMsg->ApiNumber == DbgKmExitProcessApi) {
			if (Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG) {
				DebugObject = NULL;
			}
		}
	}

	KeInitializeEvent(&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);

	DebugEvent->Process = Process;
	DebugEvent->Thread = Thread;
	DebugEvent->ApiMsg = *ApiMsg;
	DebugEvent->ClientId = Thread->Cid;

	if (DebugObject == NULL) {
		Status = STATUS_PORT_NOT_SET;
	}
	else {

		//
		// We must not use a debug port thats got no handles left.
		//
		ExAcquireFastMutex(&DebugObject->Mutex);

		//
		// If the object is delete pending then don't use this object.
		//
		if ((DebugObject->Flags&DEBUG_OBJECT_DELETE_PENDING) == 0) {
			InsertTailList(&DebugObject->EventList, &DebugEvent->EventList);
			//
			// Set the event to say there is an unread event in the object
			//
			if ((Flags&DEBUG_EVENT_NOWAIT) == 0) {
				KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
			}
			Status = STATUS_SUCCESS;
		}
		else {
			Status = STATUS_DEBUGGER_INACTIVE;
		}

		ExReleaseFastMutex(&DebugObject->Mutex);
	}


	if ((Flags&DEBUG_EVENT_NOWAIT) == 0) {
		ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);

		if (NT_SUCCESS(Status)) {
			KeWaitForSingleObject(&DebugEvent->ContinueEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);

			Status = DebugEvent->Status;
			*ApiMsg = DebugEvent->ApiMsg;
		}
	}
	else {
		if (!NT_SUCCESS(Status)) {
			ObDereferenceObject(Process);
			ObDereferenceObject(Thread);
			ExFreePool(DebugEvent);
		}
	}

	return Status;
}

VOID DbgkpMarkProcessPeb(PMyEPROCESS Process)
{
	KAPC_STATE ApcState;

	PAGED_CODE();

	//
	// Acquire process rundown protection as we are about to look at the processes address space
	//
	if (ExAcquireRundownProtection(&Process->RundownProtect)) {

		if (Process->Peb != NULL) {
			KeStackAttachProcess(&Process->Pcb, &ApcState);


			ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);

			try {
				Process->Peb->BeingDebugged = (BOOLEAN)(Process->DebugPort != NULL ? TRUE : FALSE);

			} except(EXCEPTION_EXECUTE_HANDLER) {
			}
			ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);

			KeUnstackDetachProcess(&ApcState);

		}

		ExReleaseRundownProtection(&Process->RundownProtect);
	}
}

VOID DbgkpWakeTarget(IN PDEBUG_EVENT DebugEvent)
{
	PMyETHREAD Thread;

	Thread = DebugEvent->Thread;

	if ((DebugEvent->Flags&DEBUG_EVENT_SUSPEND) != 0) {
		PsResumeThread(DebugEvent->Thread, NULL);
	}

	if (DebugEvent->Flags&DEBUG_EVENT_RELEASE) {
		ExReleaseRundownProtection(&Thread->RundownProtect);
	}

	//
	// If we have an actual thread waiting then wake it up else free the memory.
	//
	if ((DebugEvent->Flags&DEBUG_EVENT_NOWAIT) == 0) {
		KeSetEvent(&DebugEvent->ContinueEvent, 0, FALSE); // Wake up waiting process
	}
	else {
		DbgkpFreeDebugEvent(DebugEvent);
	}

	//KeAcquireInStackQueuedSpinLockRaiseToSynch(NULL, NULL);
}


VOID DbgkpFreeDebugEvent(IN PDEBUG_EVENT DebugEvent)
{
	NTSTATUS Status;

	PAGED_CODE();

	switch (DebugEvent->ApiMsg.ApiNumber) {
	case DbgKmCreateProcessApi:
		if (DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle != NULL) {
			Status = ObCloseHandle(DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
		}
		break;

	case DbgKmLoadDllApi:
		if (DebugEvent->ApiMsg.u.LoadDll.FileHandle != NULL) {
			Status = ObCloseHandle(DebugEvent->ApiMsg.u.LoadDll.FileHandle, KernelMode);
		}
		break;

	}
	ObDereferenceObject(DebugEvent->Process);
	ObDereferenceObject(DebugEvent->Thread);
	ExFreePool(DebugEvent);
}


#define ASSERT_THREAD(object) ASSERT((object)->Header.Type == ThreadObject)

#define ALERT_INCREMENT 2           // Alerted unwait priority increment
#define BALANCE_INCREMENT 10        // Balance set priority increment
#define RESUME_INCREMENT 0          // Resume thread priority increment
#define TIMER_EXPIRE_INCREMENT 0    // Timer expiration priority increment

ULONG KeResumeThread(__inout PMyETHREAD Thread)
{
	KIRQL irql =KeAcquireQueuedSpinLockRaiseToSynch(0);
	ULONG count = Thread->Tcb.SuspendCount;

	do
	{
		if (count == 0)
		{
			break;
		}
		count--;
		Thread->Tcb.SuspendCount = count;

		if (count != 0) break;
		if (Thread->Tcb.FreezeCount != 0) break;
		Thread->Tcb.SuspendSemaphore.Header.SignalState += 1;
		KiWaitTest(&Thread->Tcb.SuspendSemaphore, 0);

	} while (0);

	KiUnlockDispatcherDatabase(irql);
	return count;
}


NTSTATUS PsResumeThread(IN PMyETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL)
{
	ULONG LocalPreviousSuspendCount;

	PAGED_CODE();

	LocalPreviousSuspendCount = (ULONG)KeResumeThread(&Thread->Tcb);

	if (ARGUMENT_PRESENT(PreviousSuspendCount)) {
		*PreviousSuspendCount = LocalPreviousSuspendCount;
	}

	return STATUS_SUCCESS;
}

ULONG KeSuspendThread(__inout PKTHREAD Thread)
{
	PMyETHREAD ct = (PMyETHREAD)Thread;
	KLOCK_QUEUE_HANDLE  lockHandle = {0};
	KeAcquireInStackQueuedSpinLockRaiseToSynch(&ct->Tcb.ApcQueueLock, &lockHandle);
	PKPCR kpcr = GetCurrentKpcr();
	KeAcquireQueuedSpinLockAtDpcLevel(kpcr->Prcb->LockQueue);
	
	ULONG count = ct->Tcb.SuspendCount;
	if (count == 0x7F)
	{

		KeReleaseQueuedSpinLockFromDpcLevel(kpcr->Prcb->LockQueue);
		KeReleaseInStackQueuedSpinLock(&lockHandle);
		ExRaiseStatus(STATUS_SUSPEND_COUNT_EXCEEDED);
	}

	if (ct->Tcb.ApcQueueable == TRUE)
	{
		ct->Tcb.SuspendCount += 1;
		if (count == 0 && ct->Tcb.FreezeCount == 0)
		{
			if (!KiInsertQueueApc(&ct->Tcb.SuspendApc, 0))
			{
				ct->Tcb.SuspendSemaphore.Header.SignalState -= 1;

			}
		}
	}

	KeReleaseQueuedSpinLockFromDpcLevel(kpcr->Prcb->LockQueue);
	KeReleaseInStackQueuedSpinLock(&lockHandle);
	
	return count;
}

ULONG KeForceResumeThread(__inout PKTHREAD Thread)
{
	PMyETHREAD ct = (PMyETHREAD)Thread;
	KIRQL irql = KeAcquireQueuedSpinLockRaiseToSynch(0);
	ULONG count = ct->Tcb.SuspendCount;
	ULONG fzcount = ct->Tcb.FreezeCount;
	count += fzcount;
	
	do
	{
		if (count == 0)
		{
			break;
		}
		ct->Tcb.SuspendSemaphore.Header.SignalState += 1;
		ct->Tcb.FreezeCount = 0;
		ct->Tcb.SuspendCount = 0;
		KiWaitTest(&ct->Tcb.SuspendSemaphore, 0);
	} while (0);

	KiUnlockDispatcherDatabase(irql);
	return count;
	
}

NTSTATUS PsSuspendThread(IN PMyETHREAD Thread,OUT PULONG PreviousSuspendCount OPTIONAL)

{
	NTSTATUS Status;
	ULONG LocalPreviousSuspendCount = 0;

	PAGED_CODE();

	if (Thread == PsGetCurrentThread()) {
		try {
			LocalPreviousSuspendCount = (ULONG)KeSuspendThread(&Thread->Tcb);
			Status = STATUS_SUCCESS;
		} except((GetExceptionCode() == STATUS_SUSPEND_COUNT_EXCEEDED) ?
		EXCEPTION_EXECUTE_HANDLER :
								  EXCEPTION_CONTINUE_SEARCH) {
			Status = GetExceptionCode();
		}
	}
	else {
		//
		// Protect the remote thread from being rundown.
		//
		if (ExAcquireRundownProtection(&Thread->RundownProtect)) {

			//
			// Don't allow suspend if we are being deleted
			//
			if (Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_TERMINATED) {
				Status = STATUS_THREAD_IS_TERMINATING;
			}
			else {
				try {
					LocalPreviousSuspendCount = (ULONG)KeSuspendThread(&Thread->Tcb);
					Status = STATUS_SUCCESS;
				} except((GetExceptionCode() == STATUS_SUSPEND_COUNT_EXCEEDED) ?
				EXCEPTION_EXECUTE_HANDLER :
										  EXCEPTION_CONTINUE_SEARCH) {
					Status = GetExceptionCode();
				}
				//
				// If deletion was started after we suspended then wake up the thread
				//
				if (Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_TERMINATED) {
					KeForceResumeThread(&Thread->Tcb);
					LocalPreviousSuspendCount = 0;
					Status = STATUS_THREAD_IS_TERMINATING;
				}
			}
			ExReleaseRundownProtection(&Thread->RundownProtect);
		}
		else {
			Status = STATUS_THREAD_IS_TERMINATING;
		}
	}

	if (ARGUMENT_PRESENT(PreviousSuspendCount)) {
		*PreviousSuspendCount = LocalPreviousSuspendCount;
	}
	return Status;
}

HANDLE DbgkpSectionToFileHandle(IN PVOID SectionObject)
{

	NTSTATUS Status;
	OBJECT_ATTRIBUTES Obja;
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE Handle;
	POBJECT_NAME_INFORMATION FileNameInfo;

	PAGED_CODE();

	Status = MmGetFileNameForSection(SectionObject, &FileNameInfo);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}

	InitializeObjectAttributes(
		&Obja,
		&FileNameInfo->Name,
		OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
		);

	Status = ZwOpenFile(
		&Handle,
		(ACCESS_MASK)(GENERIC_READ | SYNCHRONIZE),
		&Obja,
		&IoStatusBlock,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SYNCHRONOUS_IO_NONALERT
		);
	ExFreePool(FileNameInfo);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}
	else {
		return Handle;
	}
}

NTSTATUS MmGetFileNameForSection(IN PSECTION SectionObject,OUT POBJECT_NAME_INFORMATION *FileNameInfo)
{
	ULONG NumberOfBytes;
	ULONG AdditionalLengthNeeded;
	NTSTATUS Status;
	PFILE_OBJECT FileObject;

	NumberOfBytes = 1024;

	*FileNameInfo = NULL;

	if (SectionObject->u.Flags.Image == 0) {
		return STATUS_SECTION_NOT_IMAGE;
	}

	*FileNameInfo = ExAllocatePoolWithTag(PagedPool, NumberOfBytes, '  mM');

	if (*FileNameInfo == NULL) {
		return STATUS_NO_MEMORY;
	}

	FileObject = SectionObject->Segment->ControlArea->FilePointer;

	Status = ObQueryNameString(FileObject,
		*FileNameInfo,
		NumberOfBytes,
		&AdditionalLengthNeeded);

	if (!NT_SUCCESS(Status)) {

		if (Status == STATUS_INFO_LENGTH_MISMATCH) {

			//
			// Our buffer was not large enough, retry just once with a larger
			// one (as specified by ObQuery).  Don't try more than once to
			// prevent broken parse procedures which give back wrong
			// AdditionalLengthNeeded values from causing problems.
			//

			ExFreePool(*FileNameInfo);

			NumberOfBytes += AdditionalLengthNeeded;

			*FileNameInfo = ExAllocatePoolWithTag(PagedPool,
				NumberOfBytes,
				'  mM');

			if (*FileNameInfo == NULL) {
				return STATUS_NO_MEMORY;
			}

			Status = ObQueryNameString(FileObject,
				*FileNameInfo,
				NumberOfBytes,
				&AdditionalLengthNeeded);

			if (NT_SUCCESS(Status)) {
				return STATUS_SUCCESS;
			}
		}

		ExFreePool(*FileNameInfo);
		*FileNameInfo = NULL;
		return Status;
	}

	return STATUS_SUCCESS;
}

NTSTATUS NtRemoveProcessDebug(IN HANDLE ProcessHandle,IN HANDLE DebugObjectHandle)

{
	NTSTATUS Status;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject;
	PEPROCESS Process;

	PAGED_CODE();

	PreviousMode = KeGetPreviousMode();

	Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_SET_PORT,
		*PsProcessType,
		PreviousMode,
		&Process,
		NULL);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}
	Status = ObReferenceObjectByHandle(DebugObjectHandle,
		DEBUG_PROCESS_ASSIGN,
		DbgkDebugObjectType,
		PreviousMode,
		&DebugObject,
		NULL);
	if (NT_SUCCESS(Status)) {
		Status = DbgkClearProcessDebugObject(Process,
			DebugObject);
		ObDereferenceObject(DebugObject);
	}

	ObDereferenceObject(Process);
	return Status;
}

NTSTATUS DbgkClearProcessDebugObject(IN PMyEPROCESS Process,IN PDEBUG_OBJECT SourceDebugObject)

{
	NTSTATUS Status;
	PDEBUG_OBJECT DebugObject;
	PDEBUG_EVENT DebugEvent;
	LIST_ENTRY TempList;
	PLIST_ENTRY Entry;

	PAGED_CODE();

	ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);

	DebugObject = Process->DebugPort;
	if (DebugObject == NULL || (DebugObject != SourceDebugObject && SourceDebugObject != NULL)) {
		DebugObject = NULL;
		Status = STATUS_PORT_NOT_SET;
	}
	else {
		Process->DebugPort = NULL;
		Status = STATUS_SUCCESS;
	}
	ExReleaseFastMutex(&DbgkpProcessDebugPortMutex);

	if (NT_SUCCESS(Status)) {
		DbgkpMarkProcessPeb(Process);
	}

	//
	// Remove any events for this process and wake up the threads.
	//
	if (DebugObject) {
		//
		// Remove any events and queue them to a temporary queue
		//
		InitializeListHead(&TempList);

		ExAcquireFastMutex(&DebugObject->Mutex);
		for (Entry = DebugObject->EventList.Flink;
			Entry != &DebugObject->EventList;
			) {

			DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
			Entry = Entry->Flink;
			if (DebugEvent->Process == Process) {
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}
		}
		ExReleaseFastMutex(&DebugObject->Mutex);

		ObDereferenceObject(DebugObject);

		//
		// Wake up all the removed threads.
		//
		while (!IsListEmpty(&TempList)) {
			Entry = RemoveHeadList(&TempList);
			DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
			DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
			DbgkpWakeTarget(DebugEvent);
		}
	}

	return Status;
}
