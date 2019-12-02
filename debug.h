#pragma once
#include "Util.h"
#include "struct.h"

#define DEBUG_OBJECT_DELETE_PENDING (0x1) // Debug object is delete pending.
#define DEBUG_OBJECT_KILL_ON_CLOSE  (0x2) // Kill all debugged processes on close

#define DEBUG_READ_EVENT        (0x0001)
#define DEBUG_PROCESS_ASSIGN    (0x0002)
#define DEBUG_SET_INFORMATION   (0x0004)
#define DEBUG_QUERY_INFORMATION (0x0008)
#define DEBUG_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|DEBUG_READ_EVENT|DEBUG_PROCESS_ASSIGN|\
                              DEBUG_SET_INFORMATION|DEBUG_QUERY_INFORMATION)

#define DEBUG_KILL_ON_CLOSE  (0x1) // Kill all debuggees on last handle close

#define PROCESS_TERMINATE         (0x0001)  // winnt
#define PROCESS_CREATE_THREAD     (0x0002)  // winnt
#define PROCESS_SET_SESSIONID     (0x0004)  // winnt
#define PROCESS_VM_OPERATION      (0x0008)  // winnt
#define PROCESS_VM_READ           (0x0010)  // winnt
#define PROCESS_VM_WRITE          (0x0020)  // winnt
// begin_ntddk begin_wdm begin_ntifs
#define PROCESS_DUP_HANDLE        (0x0040)  // winnt
// end_ntddk end_wdm end_ntifs
#define PROCESS_CREATE_PROCESS    (0x0080)  // winnt
#define PROCESS_SET_QUOTA         (0x0100)  // winnt
#define PROCESS_SET_INFORMATION   (0x0200)  // winnt
#define PROCESS_QUERY_INFORMATION (0x0400)  // winnt
#define PROCESS_SET_PORT          (0x0800)
#define PROCESS_SUSPEND_RESUME    (0x0800)  // winnt


BOOLEAN initDebugVar();

int ExSystemExceptionFilter(VOID);

typedef enum _DEBUGOBJECTINFOCLASS {
	DebugObjectFlags = 1,
	MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;


typedef struct _DEBUG_OBJECT {
	KEVENT EventsPresent;
	FAST_MUTEX Mutex;
	LIST_ENTRY EventList;
	ULONG Flags;
} DEBUG_OBJECT, *PDEBUG_OBJECT;

typedef struct _DBGKM_CREATE_THREAD {
	ULONG SubSystemKey;
	PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS {
	ULONG SubSystemKey;
	HANDLE FileHandle;
	PVOID BaseOfImage;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD {
	NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS {
	NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL {
	HANDLE FileHandle;
	PVOID BaseOfDll;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL {
	PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

typedef struct _PORT_MESSAGE {
	union {
		struct {
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union {
		struct {
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union {
		CLIENT_ID ClientId;
		double DoNotUseThisField;       // Force quadword alignment
	};
	ULONG MessageId;
	union {
		SIZE_T ClientViewSize;          // Only valid on LPC_CONNECTION_REQUEST message
		ULONG CallbackId;                   // Only valid on LPC_REQUEST message
	};
	//  UCHAR Data[];
} PORT_MESSAGE, *PPORT_MESSAGE;


typedef enum _DBGKM_APINUMBER {
	DbgKmExceptionApi,
	DbgKmCreateThreadApi,
	DbgKmCreateProcessApi,
	DbgKmExitThreadApi,
	DbgKmExitProcessApi,
	DbgKmLoadDllApi,
	DbgKmUnloadDllApi,
	DbgKmMaxApiNumber
} DBGKM_APINUMBER;

typedef struct _DBGKM_EXCEPTION {
	EXCEPTION_RECORD ExceptionRecord;
	ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_APIMSG {
	PORT_MESSAGE h;
	DBGKM_APINUMBER ApiNumber;
	NTSTATUS ReturnedStatus;
	union {
		DBGKM_EXCEPTION Exception;
		DBGKM_CREATE_THREAD CreateThread;
		DBGKM_CREATE_PROCESS CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} u;
} DBGKM_APIMSG, *PDBGKM_APIMSG;

#define DEBUG_EVENT_READ            (0x01)  // Event had been seen by win32 app
#define DEBUG_EVENT_NOWAIT          (0x02)  // No waiter one this. Just free the pool
#define DEBUG_EVENT_INACTIVE        (0x04)  // The message is in inactive. It may be activated or deleted later
#define DEBUG_EVENT_RELEASE         (0x08)  // Release rundown protection on this thread
#define DEBUG_EVENT_PROTECT_FAILED  (0x10)  // Rundown protection failed to be acquired on this thread
#define DEBUG_EVENT_SUSPEND         (0x20)  // Resume thread on continue


#define DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(hdrs,field) \
            ((hdrs)->OptionalHeader.##field)

typedef struct _DEBUG_EVENT {
	LIST_ENTRY EventList;      // Queued to event object through this
	KEVENT ContinueEvent;
	CLIENT_ID ClientId;
	PEPROCESS Process;         // Waiting process
	PETHREAD Thread;           // Waiting thread
	NTSTATUS Status;           // Status of operation
	ULONG Flags;
	PETHREAD BackoutThread;    // Backout key for faked messages
	DBGKM_APIMSG ApiMsg;       // Message being sent
} DEBUG_EVENT, *PDEBUG_EVENT;


#define KeGetPreviousMode() ExGetPreviousMode()


NTSTATUS ObCreateObject(
	__in KPROCESSOR_MODE ProbeMode,
	__in POBJECT_TYPE ObjectType,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in KPROCESSOR_MODE OwnershipMode,
	__inout_opt PVOID ParseContext,
	__in ULONG ObjectBodySize,
	__in ULONG PagedPoolCharge,
	__in ULONG NonPagedPoolCharge,
	__out PVOID *Object
);




NTSTATUS NtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
);

NTSTATUS NtDebugActiveProcess(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle
);

NTSTATUS DbgkpPostFakeProcessCreateMessages(
	IN PMyEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD *pLastThread
);

NTSTATUS DbgkpPostFakeThreadMessages(
	IN PMyEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PMyETHREAD StartThread,
	OUT PMyETHREAD *pFirstThread,
	OUT PMyETHREAD *pLastThread
);

NTSTATUS DbgkpPostFakeModuleMessages(
IN PMyEPROCESS Process,
IN PMyETHREAD Thread,
IN PDEBUG_OBJECT DebugObject);

NTSTATUS
DbgkpQueueMessage(
IN PMyEPROCESS Process,
IN PMyETHREAD Thread,
IN OUT PDBGKM_APIMSG ApiMsg,
IN ULONG Flags,
IN PDEBUG_OBJECT TargetDebugObject
);

PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

NTSTATUS
DbgkpSetProcessDebugObject(
IN PMyEPROCESS Process,
IN PDEBUG_OBJECT DebugObject,
IN NTSTATUS MsgStatus,
IN PMyETHREAD LastThread
);
VOID DbgkpFreeDebugEvent(IN PDEBUG_EVENT DebugEvent);
VOID DbgkpWakeTarget(IN PDEBUG_EVENT DebugEvent);
VOID DbgkpMarkProcessPeb(PMyEPROCESS Process);

typedef NTSTATUS (*MmGetFileNameForAddressProc)(IN PVOID ProcessVa, OUT PUNICODE_STRING FileName);

VOID PsQuitNextProcessThread(IN PETHREAD Thread);

NTSTATUS PsResumeThread(IN PMyETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
NTSTATUS PsSuspendThread(IN PMyETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
HANDLE   DbgkpSectionToFileHandle(IN PVOID SectionObject);
NTSTATUS MmGetFileNameForSection(IN PSECTION SectionObject, OUT POBJECT_NAME_INFORMATION *FileNameInfo);
NTSTATUS NtRemoveProcessDebug(IN HANDLE ProcessHandle, IN HANDLE DebugObjectHandle);
NTSTATUS DbgkClearProcessDebugObject(IN PMyEPROCESS Process, IN PDEBUG_OBJECT SourceDebugObject);


//typedef KIRQL(FASTCALL *KeAcquireQueuedSpinLockRaiseToSynchProc)(KIRQL irql);
typedef VOID (FASTCALL *KiWaitTestProc)(IN PVOID Object, IN KPRIORITY Increment);
typedef VOID(FASTCALL *KiUnlockDispatcherDatabaseProc)(KIRQL irql);

typedef PETHREAD (*PsGetNextProcessThreadProc)(IN PEPROCESS Process, IN PETHREAD Thread);


typedef VOID (FASTCALL *KeAcquireQueuedSpinLockAtDpcLevelProc)(__inout PKSPIN_LOCK_QUEUE LockQueue);

typedef VOID (FASTCALL *KeReleaseQueuedSpinLockFromDpcLevelProc)(__inout PKSPIN_LOCK_QUEUE LockQueue);

typedef BOOLEAN (FASTCALL *KiInsertQueueApcProc)(IN PKAPC Apc, IN KPRIORITY Increment);