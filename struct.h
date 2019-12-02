#pragma once
#include "Util.h"

typedef struct _KIDTENTRY        // 4 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     UINT16       Offset;
	/*0x002*/     UINT16       Selector;
	/*0x004*/     UINT16       Access;
	/*0x006*/     UINT16       ExtendedOffset;
}KIDTENTRY, *PKIDTENTRY;


typedef struct _KEXECUTE_OPTIONS            // 7 elements, 0x1 bytes (sizeof) 
{
	/*0x000*/     UINT8        ExecuteDisable : 1;        // 0 BitPosition                  
	/*0x000*/     UINT8        ExecuteEnable : 1;         // 1 BitPosition                  
	/*0x000*/     UINT8        DisableThunkEmulation : 1; // 2 BitPosition                  
	/*0x000*/     UINT8        Permanent : 1;             // 3 BitPosition                  
	/*0x000*/     UINT8        ExecuteDispatchEnable : 1; // 4 BitPosition                  
	/*0x000*/     UINT8        ImageDispatchEnable : 1;   // 5 BitPosition                  
	/*0x000*/     UINT8        Spare : 2;                 // 6 BitPosition                  
}KEXECUTE_OPTIONS, *PKEXECUTE_OPTIONS;

typedef struct _KGDTENTRY                 // 3 elements, 0x8 bytes (sizeof)  
{
	/*0x000*/     UINT16       LimitLow;
	/*0x002*/     UINT16       BaseLow;
	union                                 // 2 elements, 0x4 bytes (sizeof)  
	{
		struct                            // 4 elements, 0x4 bytes (sizeof)  
		{
			/*0x004*/             UINT8        BaseMid;
			/*0x005*/             UINT8        Flags1;
			/*0x006*/             UINT8        Flags2;
			/*0x007*/             UINT8        BaseHi;
		}Bytes;
		struct                            // 10 elements, 0x4 bytes (sizeof) 
		{
			/*0x004*/             ULONG32      BaseMid : 8;     // 0 BitPosition                   
			/*0x004*/             ULONG32      Type : 5;        // 8 BitPosition                   
			/*0x004*/             ULONG32      Dpl : 2;         // 13 BitPosition                  
			/*0x004*/             ULONG32      Pres : 1;        // 15 BitPosition                  
			/*0x004*/             ULONG32      LimitHi : 4;     // 16 BitPosition                  
			/*0x004*/             ULONG32      Sys : 1;         // 20 BitPosition                  
			/*0x004*/             ULONG32      Reserved_0 : 1;  // 21 BitPosition                  
			/*0x004*/             ULONG32      Default_Big : 1; // 22 BitPosition                  
			/*0x004*/             ULONG32      Granularity : 1; // 23 BitPosition                  
			/*0x004*/             ULONG32      BaseHi : 8;      // 24 BitPosition                  
		}Bits;
	}HighWord;
}KGDTENTRY, *PKGDTENTRY;

typedef struct _KPROCESS                     // 29 elements, 0x6C bytes (sizeof) 
{
	/*0x000*/     struct _DISPATCHER_HEADER Header;        // 6 elements, 0x10 bytes (sizeof)  
	/*0x010*/     struct _LIST_ENTRY ProfileListHead;      // 2 elements, 0x8 bytes (sizeof)   
	/*0x018*/     ULONG32      DirectoryTableBase[2];
	/*0x020*/     struct _KGDTENTRY LdtDescriptor;         // 3 elements, 0x8 bytes (sizeof)   
	/*0x028*/     struct _KIDTENTRY Int21Descriptor;       // 4 elements, 0x8 bytes (sizeof)   
	/*0x030*/     UINT16       IopmOffset;
	/*0x032*/     UINT8        Iopl;
	/*0x033*/     UINT8        Unused;
	/*0x034*/     ULONG32      ActiveProcessors;
	/*0x038*/     ULONG32      KernelTime;
	/*0x03C*/     ULONG32      UserTime;
	/*0x040*/     struct _LIST_ENTRY ReadyListHead;        // 2 elements, 0x8 bytes (sizeof)   
	/*0x048*/     struct _SINGLE_LIST_ENTRY SwapListEntry; // 1 elements, 0x4 bytes (sizeof)   
	/*0x04C*/     VOID*        VdmTrapcHandler;
	/*0x050*/     struct _LIST_ENTRY ThreadListHead;       // 2 elements, 0x8 bytes (sizeof)   
	/*0x058*/     ULONG32      ProcessLock;
	/*0x05C*/     ULONG32      Affinity;
	/*0x060*/     UINT16       StackCount;
	/*0x062*/     CHAR         BasePriority;
	/*0x063*/     CHAR         ThreadQuantum;
	/*0x064*/     UINT8        AutoAlignment;
	/*0x065*/     UINT8        State;
	/*0x066*/     UINT8        ThreadSeed;
	/*0x067*/     UINT8        DisableBoost;
	/*0x068*/     UINT8        PowerState;
	/*0x069*/     UINT8        DisableQuantum;
	/*0x06A*/     UINT8        IdealNode;
	union                                    // 2 elements, 0x1 bytes (sizeof)   
	{
		/*0x06B*/         struct _KEXECUTE_OPTIONS Flags;      // 7 elements, 0x1 bytes (sizeof)   
		/*0x06B*/         UINT8        ExecuteOptions;
	};
}KPROCESS, *PKPROCESS;

typedef struct _EX_PUSH_LOCK1            // 5 elements, 0x4 bytes (sizeof) 
{
	union                               // 3 elements, 0x4 bytes (sizeof) 
	{
		struct                          // 3 elements, 0x4 bytes (sizeof) 
		{
			/*0x000*/             ULONG32      Waiting : 1;   // 0 BitPosition                  
			/*0x000*/             ULONG32      Exclusive : 1; // 1 BitPosition                  
			/*0x000*/             ULONG32      Shared : 30;   // 2 BitPosition                  
		};
		/*0x000*/         ULONG32      Value;
		/*0x000*/         VOID*        Ptr;
	};
}EX_PUSH_LOCK1, *PEX_PUSH_LOCK1;

typedef struct _EX_FAST_REF      // 3 elements, 0x4 bytes (sizeof) 
{
	union                        // 3 elements, 0x4 bytes (sizeof) 
	{
		/*0x000*/         VOID*        Object;
		/*0x000*/         ULONG32      RefCnt : 3; // 0 BitPosition                  
		/*0x000*/         ULONG32      Value;
	};
}EX_FAST_REF, *PEX_FAST_REF;

typedef struct _HARDWARE_PTE           // 13 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Valid : 1;            // 0 BitPosition                   
	/*0x000*/     ULONG32      Write : 1;            // 1 BitPosition                   
	/*0x000*/     ULONG32      Owner : 1;            // 2 BitPosition                   
	/*0x000*/     ULONG32      WriteThrough : 1;     // 3 BitPosition                   
	/*0x000*/     ULONG32      CacheDisable : 1;     // 4 BitPosition                   
	/*0x000*/     ULONG32      Accessed : 1;         // 5 BitPosition                   
	/*0x000*/     ULONG32      Dirty : 1;            // 6 BitPosition                   
	/*0x000*/     ULONG32      LargePage : 1;        // 7 BitPosition                   
	/*0x000*/     ULONG32      Global : 1;           // 8 BitPosition                   
	/*0x000*/     ULONG32      CopyOnWrite : 1;      // 9 BitPosition                   
	/*0x000*/     ULONG32      Prototype : 1;        // 10 BitPosition                  
	/*0x000*/     ULONG32      reserved : 1;         // 11 BitPosition                  
	/*0x000*/     ULONG32      PageFrameNumber : 20; // 12 BitPosition                  
}HARDWARE_PTE, *PHARDWARE_PTE;

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO      // 1 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     struct _OBJECT_NAME_INFORMATION* ImageFileName;
}SE_AUDIT_PROCESS_CREATION_INFO, *PSE_AUDIT_PROCESS_CREATION_INFO;

typedef struct _MMSUPPORT_FLAGS                 // 9 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     UINT32       SessionSpace : 1;              // 0 BitPosition                  
	/*0x000*/     UINT32       BeingTrimmed : 1;              // 1 BitPosition                  
	/*0x000*/     UINT32       SessionLeader : 1;             // 2 BitPosition                  
	/*0x000*/     UINT32       TrimHard : 1;                  // 3 BitPosition                  
	/*0x000*/     UINT32       WorkingSetHard : 1;            // 4 BitPosition                  
	/*0x000*/     UINT32       AddressSpaceBeingDeleted : 1;  // 5 BitPosition                  
	/*0x000*/     UINT32       Available : 10;                // 6 BitPosition                  
	/*0x000*/     UINT32       AllowWorkingSetAdjustment : 8; // 16 BitPosition                 
	/*0x000*/     UINT32       MemoryPriority : 8;            // 24 BitPosition                 
}MMSUPPORT_FLAGS, *PMMSUPPORT_FLAGS;

typedef struct _MMSUPPORT                        // 14 elements, 0x40 bytes (sizeof) 
{
	/*0x000*/     union _LARGE_INTEGER LastTrimTime;           // 4 elements, 0x8 bytes (sizeof)   
	/*0x008*/     struct _MMSUPPORT_FLAGS Flags;               // 9 elements, 0x4 bytes (sizeof)   
	/*0x00C*/     ULONG32      PageFaultCount;
	/*0x010*/     ULONG32      PeakWorkingSetSize;
	/*0x014*/     ULONG32      WorkingSetSize;
	/*0x018*/     ULONG32      MinimumWorkingSetSize;
	/*0x01C*/     ULONG32      MaximumWorkingSetSize;
	/*0x020*/     struct _MMWSL* VmWorkingSetList;
	/*0x024*/     struct _LIST_ENTRY WorkingSetExpansionLinks; // 2 elements, 0x8 bytes (sizeof)   
	/*0x02C*/     ULONG32      Claim;
	/*0x030*/     ULONG32      NextEstimationSlot;
	/*0x034*/     ULONG32      NextAgingSlot;
	/*0x038*/     ULONG32      EstimatedAvailable;
	/*0x03C*/     ULONG32      GrowthSinceLastEstimate;
}MMSUPPORT, *PMMSUPPORT;

typedef struct _MyEPROCESS                                               // 107 elements, 0x260 bytes (sizeof) 
{
	/*0x000*/     struct _KPROCESS Pcb;                                              // 29 elements, 0x6C bytes (sizeof)   
	/*0x06C*/     struct _EX_PUSH_LOCK1 ProcessLock;                                  // 5 elements, 0x4 bytes (sizeof)     
	/*0x070*/     union _LARGE_INTEGER CreateTime;                                   // 4 elements, 0x8 bytes (sizeof)     
	/*0x078*/     union _LARGE_INTEGER ExitTime;                                     // 4 elements, 0x8 bytes (sizeof)     
	/*0x080*/     struct _EX_RUNDOWN_REF RundownProtect;                             // 2 elements, 0x4 bytes (sizeof)     
	/*0x084*/     VOID*        UniqueProcessId;
	/*0x088*/     struct _LIST_ENTRY ActiveProcessLinks;                             // 2 elements, 0x8 bytes (sizeof)     
	/*0x090*/     ULONG32      QuotaUsage[3];
	/*0x09C*/     ULONG32      QuotaPeak[3];
	/*0x0A8*/     ULONG32      CommitCharge;
	/*0x0AC*/     ULONG32      PeakVirtualSize;
	/*0x0B0*/     ULONG32      VirtualSize;
	/*0x0B4*/     struct _LIST_ENTRY SessionProcessLinks;                            // 2 elements, 0x8 bytes (sizeof)     
	/*0x0BC*/     VOID*        DebugPort;
	/*0x0C0*/     VOID*        ExceptionPort;
	/*0x0C4*/     struct _HANDLE_TABLE* ObjectTable;
	/*0x0C8*/     struct _EX_FAST_REF Token;                                         // 3 elements, 0x4 bytes (sizeof)     
	/*0x0CC*/     struct _FAST_MUTEX WorkingSetLock;                                 // 5 elements, 0x20 bytes (sizeof)    
	/*0x0EC*/     ULONG32      WorkingSetPage;
	/*0x0F0*/     struct _FAST_MUTEX AddressCreationLock;                            // 5 elements, 0x20 bytes (sizeof)    
	/*0x110*/     ULONG32      HyperSpaceLock;
	/*0x114*/     struct _ETHREAD* ForkInProgress;
	/*0x118*/     ULONG32      HardwareTrigger;
	/*0x11C*/     VOID*        VadRoot;
	/*0x120*/     VOID*        VadHint;
	/*0x124*/     VOID*        CloneRoot;
	/*0x128*/     ULONG32      NumberOfPrivatePages;
	/*0x12C*/     ULONG32      NumberOfLockedPages;
	/*0x130*/     VOID*        Win32Process;
	/*0x134*/     struct _EJOB* Job;
	/*0x138*/     VOID*        SectionObject;
	/*0x13C*/     VOID*        SectionBaseAddress;
	/*0x140*/     struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;
	/*0x144*/     struct _PAGEFAULT_HISTORY* WorkingSetWatch;
	/*0x148*/     VOID*        Win32WindowStation;
	/*0x14C*/     VOID*        InheritedFromUniqueProcessId;
	/*0x150*/     VOID*        LdtInformation;
	/*0x154*/     VOID*        VadFreeHint;
	/*0x158*/     VOID*        VdmObjects;
	/*0x15C*/     VOID*        DeviceMap;
	/*0x160*/     struct _LIST_ENTRY PhysicalVadList;                                // 2 elements, 0x8 bytes (sizeof)     
	union                                                              // 2 elements, 0x8 bytes (sizeof)     
	{
		/*0x168*/         struct _HARDWARE_PTE PageDirectoryPte;                         // 13 elements, 0x4 bytes (sizeof)    
		/*0x168*/         UINT64       Filler;
	};
	/*0x170*/     VOID*        Session;
	/*0x174*/     UINT8        ImageFileName[16];
	/*0x184*/     struct _LIST_ENTRY JobLinks;                                       // 2 elements, 0x8 bytes (sizeof)     
	/*0x18C*/     VOID*        LockedPagesList;
	/*0x190*/     struct _LIST_ENTRY ThreadListHead;                                 // 2 elements, 0x8 bytes (sizeof)     
	/*0x198*/     VOID*        SecurityPort;
	/*0x19C*/     VOID*        PaeTop;
	/*0x1A0*/     ULONG32      ActiveThreads;
	/*0x1A4*/     ULONG32      GrantedAccess;
	/*0x1A8*/     ULONG32      DefaultHardErrorProcessing;
	/*0x1AC*/     LONG32       LastThreadExitStatus;
	/*0x1B0*/     struct _MyPEB* Peb;
	/*0x1B4*/     struct _EX_FAST_REF PrefetchTrace;                                 // 3 elements, 0x4 bytes (sizeof)     
	/*0x1B8*/     union _LARGE_INTEGER ReadOperationCount;                           // 4 elements, 0x8 bytes (sizeof)     
	/*0x1C0*/     union _LARGE_INTEGER WriteOperationCount;                          // 4 elements, 0x8 bytes (sizeof)     
	/*0x1C8*/     union _LARGE_INTEGER OtherOperationCount;                          // 4 elements, 0x8 bytes (sizeof)     
	/*0x1D0*/     union _LARGE_INTEGER ReadTransferCount;                            // 4 elements, 0x8 bytes (sizeof)     
	/*0x1D8*/     union _LARGE_INTEGER WriteTransferCount;                           // 4 elements, 0x8 bytes (sizeof)     
	/*0x1E0*/     union _LARGE_INTEGER OtherTransferCount;                           // 4 elements, 0x8 bytes (sizeof)     
	/*0x1E8*/     ULONG32      CommitChargeLimit;
	/*0x1EC*/     ULONG32      CommitChargePeak;
	/*0x1F0*/     VOID*        AweInfo;
	/*0x1F4*/     struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo; // 1 elements, 0x4 bytes (sizeof)     
	/*0x1F8*/     struct _MMSUPPORT Vm;                                              // 14 elements, 0x40 bytes (sizeof)   
	/*0x238*/     ULONG32      LastFaultCount;
	/*0x23C*/     ULONG32      ModifiedPageCount;
	/*0x240*/     ULONG32      NumberOfVads;
	/*0x244*/     ULONG32      JobStatus;
	union                                                              // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x248*/         ULONG32      Flags;
		struct                                                         // 27 elements, 0x4 bytes (sizeof)    
		{
			/*0x248*/             ULONG32      CreateReported : 1;                           // 0 BitPosition                      
			/*0x248*/             ULONG32      NoDebugInherit : 1;                           // 1 BitPosition                      
			/*0x248*/             ULONG32      ProcessExiting : 1;                           // 2 BitPosition                      
			/*0x248*/             ULONG32      ProcessDelete : 1;                            // 3 BitPosition                      
			/*0x248*/             ULONG32      Wow64SplitPages : 1;                          // 4 BitPosition                      
			/*0x248*/             ULONG32      VmDeleted : 1;                                // 5 BitPosition                      
			/*0x248*/             ULONG32      OutswapEnabled : 1;                           // 6 BitPosition                      
			/*0x248*/             ULONG32      Outswapped : 1;                               // 7 BitPosition                      
			/*0x248*/             ULONG32      ForkFailed : 1;                               // 8 BitPosition                      
			/*0x248*/             ULONG32      HasPhysicalVad : 1;                           // 9 BitPosition                      
			/*0x248*/             ULONG32      AddressSpaceInitialized : 2;                  // 10 BitPosition                     
			/*0x248*/             ULONG32      SetTimerResolution : 1;                       // 12 BitPosition                     
			/*0x248*/             ULONG32      BreakOnTermination : 1;                       // 13 BitPosition                     
			/*0x248*/             ULONG32      SessionCreationUnderway : 1;                  // 14 BitPosition                     
			/*0x248*/             ULONG32      WriteWatch : 1;                               // 15 BitPosition                     
			/*0x248*/             ULONG32      ProcessInSession : 1;                         // 16 BitPosition                     
			/*0x248*/             ULONG32      OverrideAddressSpace : 1;                     // 17 BitPosition                     
			/*0x248*/             ULONG32      HasAddressSpace : 1;                          // 18 BitPosition                     
			/*0x248*/             ULONG32      LaunchPrefetched : 1;                         // 19 BitPosition                     
			/*0x248*/             ULONG32      InjectInpageErrors : 1;                       // 20 BitPosition                     
			/*0x248*/             ULONG32      VmTopDown : 1;                                // 21 BitPosition                     
			/*0x248*/             ULONG32      Unused3 : 1;                                  // 22 BitPosition                     
			/*0x248*/             ULONG32      Unused4 : 1;                                  // 23 BitPosition                     
			/*0x248*/             ULONG32      VdmAllowed : 1;                               // 24 BitPosition                     
			/*0x248*/             ULONG32      Unused : 5;                                   // 25 BitPosition                     
			/*0x248*/             ULONG32      Unused1 : 1;                                  // 30 BitPosition                     
			/*0x248*/             ULONG32      Unused2 : 1;                                  // 31 BitPosition                     
		};
	};
	/*0x24C*/     LONG32       ExitStatus;
	/*0x250*/     UINT16       NextPageColor;
	union                                                              // 2 elements, 0x2 bytes (sizeof)     
	{
		struct                                                         // 2 elements, 0x2 bytes (sizeof)     
		{
			/*0x252*/             UINT8        SubSystemMinorVersion;
			/*0x253*/             UINT8        SubSystemMajorVersion;
		};
		/*0x252*/         UINT16       SubSystemVersion;
	};
	/*0x254*/     UINT8        PriorityClass;
	/*0x255*/     UINT8        WorkingSetAcquiredUnsafe;
	/*0x256*/     UINT8        _PADDING0_[0x2];
	/*0x258*/     ULONG32      Cookie;
	/*0x25C*/     UINT8        _PADDING1_[0x4];
}MyEPROCESS, *PMyEPROCESS;


typedef struct _PEB_LDR_DATA                            // 7 elements, 0x28 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Length;
	/*0x004*/     UINT8        Initialized;
	/*0x005*/     UINT8        _PADDING0_[0x3];
	/*0x008*/     VOID*        SsHandle;
	/*0x00C*/     struct _LIST_ENTRY InLoadOrderModuleList;           // 2 elements, 0x8 bytes (sizeof)  
	/*0x014*/     struct _LIST_ENTRY InMemoryOrderModuleList;         // 2 elements, 0x8 bytes (sizeof)  
	/*0x01C*/     struct _LIST_ENTRY InInitializationOrderModuleList; // 2 elements, 0x8 bytes (sizeof)  
	/*0x024*/     VOID*        EntryInProgress;
}PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY               // 18 elements, 0x50 bytes (sizeof) 
{
	/*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;           // 2 elements, 0x8 bytes (sizeof)   
	/*0x008*/     struct _LIST_ENTRY InMemoryOrderLinks;         // 2 elements, 0x8 bytes (sizeof)   
	/*0x010*/     struct _LIST_ENTRY InInitializationOrderLinks; // 2 elements, 0x8 bytes (sizeof)   
	/*0x018*/     VOID*        DllBase;
	/*0x01C*/     VOID*        EntryPoint;
	/*0x020*/     ULONG32      SizeOfImage;
	/*0x024*/     struct _UNICODE_STRING FullDllName;            // 3 elements, 0x8 bytes (sizeof)   
	/*0x02C*/     struct _UNICODE_STRING BaseDllName;            // 3 elements, 0x8 bytes (sizeof)   
	/*0x034*/     ULONG32      Flags;
	/*0x038*/     UINT16       LoadCount;
	/*0x03A*/     UINT16       TlsIndex;
	union                                          // 2 elements, 0x8 bytes (sizeof)   
	{
		/*0x03C*/         struct _LIST_ENTRY HashLinks;              // 2 elements, 0x8 bytes (sizeof)   
		struct                                     // 2 elements, 0x8 bytes (sizeof)   
		{
			/*0x03C*/             VOID*        SectionPointer;
			/*0x040*/             ULONG32      CheckSum;
		};
	};
	union                                          // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x044*/         ULONG32      TimeDateStamp;
		/*0x044*/         VOID*        LoadedImports;
	};
	/*0x048*/     VOID*        EntryPointActivationContext;
	/*0x04C*/     VOID*        PatchInformation;
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef VOID(NTAPI * FUNCT_00BC_062E_PostProcessInitRoutine_DispatchAddress_FinishRoutine) ();

typedef struct _MyPEB                                                                               // 65 elements, 0x210 bytes (sizeof) 
{
	/*0x000*/     UINT8        InheritedAddressSpace;
	/*0x001*/     UINT8        ReadImageFileExecOptions;
	/*0x002*/     UINT8        BeingDebugged;
	/*0x003*/     UINT8        SpareBool;
	/*0x004*/     VOID*        Mutant;
	/*0x008*/     VOID*        ImageBaseAddress;
	/*0x00C*/     struct _PEB_LDR_DATA* Ldr;
	/*0x010*/     struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
	/*0x014*/     VOID*        SubSystemData;
	/*0x018*/     VOID*        ProcessHeap;
	/*0x01C*/     struct _RTL_CRITICAL_SECTION* FastPebLock;
	/*0x020*/     VOID*        FastPebLockRoutine;
	/*0x024*/     VOID*        FastPebUnlockRoutine;
	/*0x028*/     ULONG32      EnvironmentUpdateCount;
	/*0x02C*/     VOID*        KernelCallbackTable;
	/*0x030*/     ULONG32      SystemReserved[1];
	/*0x034*/     ULONG32      AtlThunkSListPtr32;
	/*0x038*/     struct _PEB_FREE_BLOCK* FreeList;
	/*0x03C*/     ULONG32      TlsExpansionCounter;
	/*0x040*/     VOID*        TlsBitmap;
	/*0x044*/     ULONG32      TlsBitmapBits[2];
	/*0x04C*/     VOID*        ReadOnlySharedMemoryBase;
	/*0x050*/     VOID*        ReadOnlySharedMemoryHeap;
	/*0x054*/     VOID**       ReadOnlyStaticServerData;
	/*0x058*/     VOID*        AnsiCodePageData;
	/*0x05C*/     VOID*        OemCodePageData;
	/*0x060*/     VOID*        UnicodeCaseTableData;
	/*0x064*/     ULONG32      NumberOfProcessors;
	/*0x068*/     ULONG32      NtGlobalFlag;
	/*0x06C*/     UINT8        _PADDING0_[0x4];
	/*0x070*/     union _LARGE_INTEGER CriticalSectionTimeout;                                                  // 4 elements, 0x8 bytes (sizeof)    
	/*0x078*/     ULONG32      HeapSegmentReserve;
	/*0x07C*/     ULONG32      HeapSegmentCommit;
	/*0x080*/     ULONG32      HeapDeCommitTotalFreeThreshold;
	/*0x084*/     ULONG32      HeapDeCommitFreeBlockThreshold;
	/*0x088*/     ULONG32      NumberOfHeaps;
	/*0x08C*/     ULONG32      MaximumNumberOfHeaps;
	/*0x090*/     VOID**       ProcessHeaps;
	/*0x094*/     VOID*        GdiSharedHandleTable;
	/*0x098*/     VOID*        ProcessStarterHelper;
	/*0x09C*/     ULONG32      GdiDCAttributeList;
	/*0x0A0*/     VOID*        LoaderLock;
	/*0x0A4*/     ULONG32      OSMajorVersion;
	/*0x0A8*/     ULONG32      OSMinorVersion;
	/*0x0AC*/     UINT16       OSBuildNumber;
	/*0x0AE*/     UINT16       OSCSDVersion;
	/*0x0B0*/     ULONG32      OSPlatformId;
	/*0x0B4*/     ULONG32      ImageSubsystem;
	/*0x0B8*/     ULONG32      ImageSubsystemMajorVersion;
	/*0x0BC*/     ULONG32      ImageSubsystemMinorVersion;
	/*0x0C0*/     ULONG32      ImageProcessAffinityMask;
	/*0x0C4*/     ULONG32      GdiHandleBuffer[34];
	/*0x14C*/     FUNCT_00BC_062E_PostProcessInitRoutine_DispatchAddress_FinishRoutine* PostProcessInitRoutine;
	/*0x150*/     VOID*        TlsExpansionBitmap;
	/*0x154*/     ULONG32      TlsExpansionBitmapBits[32];
	/*0x1D4*/     ULONG32      SessionId;
	/*0x1D8*/     union _ULARGE_INTEGER AppCompatFlags;                                                         // 4 elements, 0x8 bytes (sizeof)    
	/*0x1E0*/     union _ULARGE_INTEGER AppCompatFlagsUser;                                                     // 4 elements, 0x8 bytes (sizeof)    
	/*0x1E8*/     VOID*        pShimData;
	/*0x1EC*/     VOID*        AppCompatInfo;
	/*0x1F0*/     struct _UNICODE_STRING CSDVersion;                                                            // 3 elements, 0x8 bytes (sizeof)    
	/*0x1F8*/     VOID*        ActivationContextData;
	/*0x1FC*/     VOID*        ProcessAssemblyStorageMap;
	/*0x200*/     VOID*        SystemDefaultActivationContextData;
	/*0x204*/     VOID*        SystemAssemblyStorageMap;
	/*0x208*/     ULONG32      MinimumStackCommit;
	/*0x20C*/     UINT8        _PADDING1_[0x4];
}MyPEB, *PMyPEB;


typedef struct _KTHREAD                          // 73 elements, 0x1C0 bytes (sizeof) 
{
	/*0x000*/     struct _DISPATCHER_HEADER Header;            // 6 elements, 0x10 bytes (sizeof)   
	/*0x010*/     struct _LIST_ENTRY MutantListHead;           // 2 elements, 0x8 bytes (sizeof)    
	/*0x018*/     VOID*        InitialStack;
	/*0x01C*/     VOID*        StackLimit;
	/*0x020*/     VOID*        Teb;
	/*0x024*/     VOID*        TlsArray;
	/*0x028*/     VOID*        KernelStack;
	/*0x02C*/     UINT8        DebugActive;
	/*0x02D*/     UINT8        State;
	/*0x02E*/     UINT8        Alerted[2];
	/*0x030*/     UINT8        Iopl;
	/*0x031*/     UINT8        NpxState;
	/*0x032*/     CHAR         Saturation;
	/*0x033*/     CHAR         Priority;
	/*0x034*/     struct _KAPC_STATE ApcState;                 // 5 elements, 0x18 bytes (sizeof)   
	/*0x04C*/     ULONG32      ContextSwitches;
	/*0x050*/     UINT8        IdleSwapBlock;
	/*0x051*/     UINT8        Spare0[3];
	/*0x054*/     LONG32       WaitStatus;
	/*0x058*/     UINT8        WaitIrql;
	/*0x059*/     CHAR         WaitMode;
	/*0x05A*/     UINT8        WaitNext;
	/*0x05B*/     UINT8        WaitReason;
	/*0x05C*/     struct _KWAIT_BLOCK* WaitBlockList;
	union                                        // 2 elements, 0x8 bytes (sizeof)    
	{
		/*0x060*/         struct _LIST_ENTRY WaitListEntry;        // 2 elements, 0x8 bytes (sizeof)    
		/*0x060*/         struct _SINGLE_LIST_ENTRY SwapListEntry; // 1 elements, 0x4 bytes (sizeof)    
	};
	/*0x068*/     ULONG32      WaitTime;
	/*0x06C*/     CHAR         BasePriority;
	/*0x06D*/     UINT8        DecrementCount;
	/*0x06E*/     CHAR         PriorityDecrement;
	/*0x06F*/     CHAR         Quantum;
	/*0x070*/     struct _KWAIT_BLOCK WaitBlock[4];
	/*0x0D0*/     VOID*        LegoData;
	/*0x0D4*/     ULONG32      KernelApcDisable;
	/*0x0D8*/     ULONG32      UserAffinity;
	/*0x0DC*/     UINT8        SystemAffinityActive;
	/*0x0DD*/     UINT8        PowerState;
	/*0x0DE*/     UINT8        NpxIrql;
	/*0x0DF*/     UINT8        InitialNode;
	/*0x0E0*/     VOID*        ServiceTable;
	/*0x0E4*/     struct _KQUEUE* Queue;
	/*0x0E8*/     ULONG32      ApcQueueLock;
	/*0x0EC*/     UINT8        _PADDING0_[0x4];
	/*0x0F0*/     struct _KTIMER Timer;                        // 5 elements, 0x28 bytes (sizeof)   
	/*0x118*/     struct _LIST_ENTRY QueueListEntry;           // 2 elements, 0x8 bytes (sizeof)    
	/*0x120*/     ULONG32      SoftAffinity;
	/*0x124*/     ULONG32      Affinity;
	/*0x128*/     UINT8        Preempted;
	/*0x129*/     UINT8        ProcessReadyQueue;
	/*0x12A*/     UINT8        KernelStackResident;
	/*0x12B*/     UINT8        NextProcessor;
	/*0x12C*/     VOID*        CallbackStack;
	/*0x130*/     VOID*        Win32Thread;
	/*0x134*/     struct _KTRAP_FRAME* TrapFrame;
	/*0x138*/     struct _KAPC_STATE* ApcStatePointer[2];
	/*0x140*/     CHAR         PreviousMode;
	/*0x141*/     UINT8        EnableStackSwap;
	/*0x142*/     UINT8        LargeStack;
	/*0x143*/     UINT8        ResourceIndex;
	/*0x144*/     ULONG32      KernelTime;
	/*0x148*/     ULONG32      UserTime;
	/*0x14C*/     struct _KAPC_STATE SavedApcState;            // 5 elements, 0x18 bytes (sizeof)   
	/*0x164*/     UINT8        Alertable;
	/*0x165*/     UINT8        ApcStateIndex;
	/*0x166*/     UINT8        ApcQueueable;
	/*0x167*/     UINT8        AutoAlignment;
	/*0x168*/     VOID*        StackBase;
	/*0x16C*/     struct _KAPC SuspendApc;                     // 14 elements, 0x30 bytes (sizeof)  
	/*0x19C*/     struct _KSEMAPHORE SuspendSemaphore;         // 2 elements, 0x14 bytes (sizeof)   
	/*0x1B0*/     struct _LIST_ENTRY ThreadListEntry;          // 2 elements, 0x8 bytes (sizeof)    
	/*0x1B8*/     CHAR         FreezeCount;
	/*0x1B9*/     CHAR         SuspendCount;
	/*0x1BA*/     UINT8        IdealProcessor;
	/*0x1BB*/     UINT8        DisableBoost;
	/*0x1BC*/     UINT8        _PADDING1_[0x4];
}KTHREAD, *PKTHREAD;

typedef struct _MYETHREAD                                      // 54 elements, 0x258 bytes (sizeof) 
{
	/*0x000*/     struct _KTHREAD Tcb;                                     // 73 elements, 0x1C0 bytes (sizeof) 
	union                                                    // 2 elements, 0x8 bytes (sizeof)    
	{
		/*0x1C0*/         union _LARGE_INTEGER CreateTime;                     // 4 elements, 0x8 bytes (sizeof)    
		struct                                               // 2 elements, 0x4 bytes (sizeof)    
		{
			/*0x1C0*/             UINT32       NestedFaultCount : 2;               // 0 BitPosition                     
			/*0x1C0*/             UINT32       ApcNeeded : 1;                      // 2 BitPosition                     
		};
	};
	union                                                    // 3 elements, 0x8 bytes (sizeof)    
	{
		/*0x1C8*/         union _LARGE_INTEGER ExitTime;                       // 4 elements, 0x8 bytes (sizeof)    
		/*0x1C8*/         struct _LIST_ENTRY LpcReplyChain;                    // 2 elements, 0x8 bytes (sizeof)    
		/*0x1C8*/         struct _LIST_ENTRY KeyedWaitChain;                   // 2 elements, 0x8 bytes (sizeof)    
	};
	union                                                    // 2 elements, 0x4 bytes (sizeof)    
	{
		/*0x1D0*/         LONG32       ExitStatus;
		/*0x1D0*/         VOID*        OfsChain;
	};
	/*0x1D4*/     struct _LIST_ENTRY PostBlockList;                        // 2 elements, 0x8 bytes (sizeof)    
	union                                                    // 3 elements, 0x4 bytes (sizeof)    
	{
		/*0x1DC*/         struct _TERMINATION_PORT* TerminationPort;
		/*0x1DC*/         struct _ETHREAD* ReaperLink;
		/*0x1DC*/         VOID*        KeyedWaitValue;
	};
	/*0x1E0*/     ULONG32      ActiveTimerListLock;
	/*0x1E4*/     struct _LIST_ENTRY ActiveTimerListHead;                  // 2 elements, 0x8 bytes (sizeof)    
	/*0x1EC*/     struct _CLIENT_ID Cid;                                   // 2 elements, 0x8 bytes (sizeof)    
	union                                                    // 2 elements, 0x14 bytes (sizeof)   
	{
		/*0x1F4*/         struct _KSEMAPHORE LpcReplySemaphore;                // 2 elements, 0x14 bytes (sizeof)   
		/*0x1F4*/         struct _KSEMAPHORE KeyedWaitSemaphore;               // 2 elements, 0x14 bytes (sizeof)   
	};
	union                                                    // 2 elements, 0x4 bytes (sizeof)    
	{
		/*0x208*/         VOID*        LpcReplyMessage;
		/*0x208*/         VOID*        LpcWaitingOnPort;
	};
	/*0x20C*/     struct _PS_IMPERSONATION_INFORMATION* ImpersonationInfo;
	/*0x210*/     struct _LIST_ENTRY IrpList;                              // 2 elements, 0x8 bytes (sizeof)    
	/*0x218*/     ULONG32      TopLevelIrp;
	/*0x21C*/     struct _DEVICE_OBJECT* DeviceToVerify;
	/*0x220*/     struct _EPROCESS* ThreadsProcess;
	/*0x224*/     VOID*        StartAddress;
	union                                                    // 2 elements, 0x4 bytes (sizeof)    
	{
		/*0x228*/         VOID*        Win32StartAddress;
		/*0x228*/         ULONG32      LpcReceivedMessageId;
	};
	/*0x22C*/     struct _LIST_ENTRY ThreadListEntry;                      // 2 elements, 0x8 bytes (sizeof)    
	/*0x234*/     struct _EX_RUNDOWN_REF RundownProtect;                   // 2 elements, 0x4 bytes (sizeof)    
	/*0x238*/     struct _EX_PUSH_LOCK1 ThreadLock;                         // 5 elements, 0x4 bytes (sizeof)    
	/*0x23C*/     ULONG32      LpcReplyMessageId;
	/*0x240*/     ULONG32      ReadClusterSize;
	/*0x244*/     ULONG32      GrantedAccess;
	union                                                    // 2 elements, 0x4 bytes (sizeof)    
	{
		/*0x248*/         ULONG32      CrossThreadFlags;
		struct                                               // 9 elements, 0x4 bytes (sizeof)    
		{
			/*0x248*/             ULONG32      Terminated : 1;                     // 0 BitPosition                     
			/*0x248*/             ULONG32      DeadThread : 1;                     // 1 BitPosition                     
			/*0x248*/             ULONG32      HideFromDebugger : 1;               // 2 BitPosition                     
			/*0x248*/             ULONG32      ActiveImpersonationInfo : 1;        // 3 BitPosition                     
			/*0x248*/             ULONG32      SystemThread : 1;                   // 4 BitPosition                     
			/*0x248*/             ULONG32      HardErrorsAreDisabled : 1;          // 5 BitPosition                     
			/*0x248*/             ULONG32      BreakOnTermination : 1;             // 6 BitPosition                     
			/*0x248*/             ULONG32      SkipCreationMsg : 1;                // 7 BitPosition                     
			/*0x248*/             ULONG32      SkipTerminationMsg : 1;             // 8 BitPosition                     
		};
	};
	union                                                    // 2 elements, 0x4 bytes (sizeof)    
	{
		/*0x24C*/         ULONG32      SameThreadPassiveFlags;
		struct                                               // 3 elements, 0x4 bytes (sizeof)    
		{
			/*0x24C*/             ULONG32      ActiveExWorker : 1;                 // 0 BitPosition                     
			/*0x24C*/             ULONG32      ExWorkerCanWaitUser : 1;            // 1 BitPosition                     
			/*0x24C*/             ULONG32      MemoryMaker : 1;                    // 2 BitPosition                     
		};
	};
	union                                                    // 2 elements, 0x4 bytes (sizeof)    
	{
		/*0x250*/         ULONG32      SameThreadApcFlags;
		struct                                               // 3 elements, 0x1 bytes (sizeof)    
		{
			/*0x250*/             UINT8        LpcReceivedMsgIdValid : 1;          // 0 BitPosition                     
			/*0x250*/             UINT8        LpcExitThreadCalled : 1;            // 1 BitPosition                     
			/*0x250*/             UINT8        AddressSpaceOwner : 1;              // 2 BitPosition                     
		};
	};
	/*0x254*/     UINT8        ForwardClusterOnly;
	/*0x255*/     UINT8        DisablePageFaultClustering;
	/*0x256*/     UINT8        _PADDING0_[0x2];
}MyETHREAD, *PMyETHREAD;


#define PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG 0x1
#define PS_CROSS_THREAD_FLAGS_TERMINATED 0x1
#define PS_CROSS_THREAD_FLAGS_SYSTEM 0x10
#define PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG 0x80

#define PS_PROCESS_FLAGS_CREATE_REPORTED        0x00000001UL // Create process debug call has occurred
#define PS_PROCESS_FLAGS_NO_DEBUG_INHERIT       0x00000002UL // Don't inherit debug port
#define PS_PROCESS_FLAGS_PROCESS_EXITING        0x00000004UL // PspExitProcess entered
#define PS_PROCESS_FLAGS_PROCESS_DELETE         0x00000008UL // Delete process has been issued
#define PS_PROCESS_FLAGS_WOW64_SPLIT_PAGES      0x00000010UL // Wow64 split pages
#define PS_PROCESS_FLAGS_VM_DELETED             0x00000020UL // VM is deleted
#define PS_PROCESS_FLAGS_OUTSWAP_ENABLED        0x00000040UL // Outswap enabled
#define PS_PROCESS_FLAGS_OUTSWAPPED             0x00000080UL // Outswapped
#define PS_PROCESS_FLAGS_FORK_FAILED            0x00000100UL // Fork status
#define PS_PROCESS_FLAGS_WOW64_4GB_VA_SPACE     0x00000200UL // Wow64 process with 4gb virtual address space
#define PS_PROCESS_FLAGS_ADDRESS_SPACE1         0x00000400UL // Addr space state1
#define PS_PROCESS_FLAGS_ADDRESS_SPACE2         0x00000800UL // Addr space state2
#define PS_PROCESS_FLAGS_SET_TIMER_RESOLUTION   0x00001000UL // SetTimerResolution has been called
#define PS_PROCESS_FLAGS_BREAK_ON_TERMINATION   0x00002000UL // Break on process termination
#define PS_PROCESS_FLAGS_CREATING_SESSION       0x00004000UL // Process is creating a session
#define PS_PROCESS_FLAGS_USING_WRITE_WATCH      0x00008000UL // Process is using the write watch APIs
#define PS_PROCESS_FLAGS_IN_SESSION             0x00010000UL // Process is in a session
#define PS_PROCESS_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00020000UL // Process must use native address space (Win64 only)
#define PS_PROCESS_FLAGS_HAS_ADDRESS_SPACE      0x00040000UL // This process has an address space
#define PS_PROCESS_FLAGS_LAUNCH_PREFETCHED      0x00080000UL // Process launch was prefetched
#define PS_PROCESS_INJECT_INPAGE_ERRORS         0x00100000UL // Process should be given inpage errors - hardcoded in trap.asm too
#define PS_PROCESS_FLAGS_VM_TOP_DOWN            0x00200000UL // Process memory allocations default to top-down
#define PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE      0x00400000UL // We have sent a message for this image
#define PS_PROCESS_FLAGS_PDE_UPDATE_NEEDED      0x00800000UL // The system PDEs need updating for this process (NT32 only)
#define PS_PROCESS_FLAGS_VDM_ALLOWED            0x01000000UL // Process allowed to invoke NTVDM support
#define PS_PROCESS_FLAGS_SMAP_ALLOWED           0x02000000UL // Process allowed to invoke SMAP support
#define PS_PROCESS_FLAGS_CREATE_FAILED          0x04000000UL // Process create failed

#define PS_PROCESS_FLAGS_DEFAULT_IO_PRIORITY    0x38000000UL // The default I/O priority for created threads. (3 bits)

#define PS_PROCESS_FLAGS_PRIORITY_SHIFT         27

#define PS_PROCESS_FLAGS_EXECUTE_SPARE1         0x40000000UL //
#define PS_PROCESS_FLAGS_EXECUTE_SPARE2         0x80000000UL //

#define IS_SYSTEM_THREAD(Thread)  (((Thread)->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SYSTEM) != 0)

#define PS_SET_BITS(Flags, Flag) \
    RtlInterlockedSetBitsDiscardReturn (Flags, Flag)



typedef enum _KOBJECTS {
	EventNotificationObject = 0,
	EventSynchronizationObject = 1,
	MutantObject = 2,
	ProcessObject = 3,
	QueueObject = 4,
	SemaphoreObject = 5,
	ThreadObject = 6,
	GateObject = 7,
	TimerNotificationObject = 8,
	TimerSynchronizationObject = 9,
	Spare2Object = 10,
	Spare3Object = 11,
	Spare4Object = 12,
	Spare5Object = 13,
	Spare6Object = 14,
	Spare7Object = 15,
	Spare8Object = 16,
	Spare9Object = 17,
	ApcObject,
	DpcObject,
	DeviceQueueObject,
	EventPairObject,
	InterruptObject,
	ProfileObject,
	ThreadedDpcObject,
	MaximumKernelObject
} KOBJECTS;
typedef struct _MMSECTION_FLAGS                // 31 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     UINT32       BeingDeleted : 1;             // 0 BitPosition                   
	/*0x000*/     UINT32       BeingCreated : 1;             // 1 BitPosition                   
	/*0x000*/     UINT32       BeingPurged : 1;              // 2 BitPosition                   
	/*0x000*/     UINT32       NoModifiedWriting : 1;        // 3 BitPosition                   
	/*0x000*/     UINT32       FailAllIo : 1;                // 4 BitPosition                   
	/*0x000*/     UINT32       Image : 1;                    // 5 BitPosition                   
	/*0x000*/     UINT32       Based : 1;                    // 6 BitPosition                   
	/*0x000*/     UINT32       File : 1;                     // 7 BitPosition                   
	/*0x000*/     UINT32       Networked : 1;                // 8 BitPosition                   
	/*0x000*/     UINT32       NoCache : 1;                  // 9 BitPosition                   
	/*0x000*/     UINT32       PhysicalMemory : 1;           // 10 BitPosition                  
	/*0x000*/     UINT32       CopyOnWrite : 1;              // 11 BitPosition                  
	/*0x000*/     UINT32       Reserve : 1;                  // 12 BitPosition                  
	/*0x000*/     UINT32       Commit : 1;                   // 13 BitPosition                  
	/*0x000*/     UINT32       FloppyMedia : 1;              // 14 BitPosition                  
	/*0x000*/     UINT32       WasPurged : 1;                // 15 BitPosition                  
	/*0x000*/     UINT32       UserReference : 1;            // 16 BitPosition                  
	/*0x000*/     UINT32       GlobalMemory : 1;             // 17 BitPosition                  
	/*0x000*/     UINT32       DeleteOnClose : 1;            // 18 BitPosition                  
	/*0x000*/     UINT32       FilePointerNull : 1;          // 19 BitPosition                  
	/*0x000*/     UINT32       DebugSymbolsLoaded : 1;       // 20 BitPosition                  
	/*0x000*/     UINT32       SetMappedFileIoComplete : 1;  // 21 BitPosition                  
	/*0x000*/     UINT32       CollidedFlush : 1;            // 22 BitPosition                  
	/*0x000*/     UINT32       NoChange : 1;                 // 23 BitPosition                  
	/*0x000*/     UINT32       HadUserReference : 1;         // 24 BitPosition                  
	/*0x000*/     UINT32       ImageMappedInSystemSpace : 1; // 25 BitPosition                  
	/*0x000*/     UINT32       UserWritable : 1;             // 26 BitPosition                  
	/*0x000*/     UINT32       Accessed : 1;                 // 27 BitPosition                  
	/*0x000*/     UINT32       GlobalOnlyPerSession : 1;     // 28 BitPosition                  
	/*0x000*/     UINT32       Rom : 1;                      // 29 BitPosition                  
	/*0x000*/     UINT32       filler : 2;                   // 30 BitPosition                  
}MMSECTION_FLAGS, *PMMSECTION_FLAGS;

typedef struct _MMADDRESS_NODE {
	union {
		LONG_PTR Balance : 2;
		struct _MMADDRESS_NODE *Parent;
	} u1;
	struct _MMADDRESS_NODE *LeftChild;
	struct _MMADDRESS_NODE *RightChild;
	ULONG_PTR StartingVpn;
	ULONG_PTR EndingVpn;
} MMADDRESS_NODE, *PMMADDRESS_NODE;




typedef struct _MMPTE_HARDWARE         // 13 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Valid : 1;            // 0 BitPosition                   
	/*0x000*/     ULONG32      Writable : 1;         // 1 BitPosition                   
	/*0x000*/     ULONG32      Owner : 1;            // 2 BitPosition                   
	/*0x000*/     ULONG32      WriteThrough : 1;     // 3 BitPosition                   
	/*0x000*/     ULONG32      CacheDisable : 1;     // 4 BitPosition                   
	/*0x000*/     ULONG32      Accessed : 1;         // 5 BitPosition                   
	/*0x000*/     ULONG32      Dirty : 1;            // 6 BitPosition                   
	/*0x000*/     ULONG32      LargePage : 1;        // 7 BitPosition                   
	/*0x000*/     ULONG32      Global : 1;           // 8 BitPosition                   
	/*0x000*/     ULONG32      CopyOnWrite : 1;      // 9 BitPosition                   
	/*0x000*/     ULONG32      Prototype : 1;        // 10 BitPosition                  
	/*0x000*/     ULONG32      Write : 1;            // 11 BitPosition                  
	/*0x000*/     ULONG32      PageFrameNumber : 20; // 12 BitPosition                  
}MMPTE_HARDWARE, *PMMPTE_HARDWARE;

typedef struct _MMPTE_PROTOTYPE         // 6 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Valid : 1;             // 0 BitPosition                  
	/*0x000*/     ULONG32      ProtoAddressLow : 7;   // 1 BitPosition                  
	/*0x000*/     ULONG32      ReadOnly : 1;          // 8 BitPosition                  
	/*0x000*/     ULONG32      WhichPool : 1;         // 9 BitPosition                  
	/*0x000*/     ULONG32      Prototype : 1;         // 10 BitPosition                 
	/*0x000*/     ULONG32      ProtoAddressHigh : 21; // 11 BitPosition                 
}MMPTE_PROTOTYPE, *PMMPTE_PROTOTYPE;

typedef struct _MMPTE_SOFTWARE      // 6 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Valid : 1;         // 0 BitPosition                  
	/*0x000*/     ULONG32      PageFileLow : 4;   // 1 BitPosition                  
	/*0x000*/     ULONG32      Protection : 5;    // 5 BitPosition                  
	/*0x000*/     ULONG32      Prototype : 1;     // 10 BitPosition                 
	/*0x000*/     ULONG32      Transition : 1;    // 11 BitPosition                 
	/*0x000*/     ULONG32      PageFileHigh : 20; // 12 BitPosition                 
}MMPTE_SOFTWARE, *PMMPTE_SOFTWARE;

typedef struct _MMPTE_TRANSITION       // 9 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Valid : 1;            // 0 BitPosition                  
	/*0x000*/     ULONG32      Write : 1;            // 1 BitPosition                  
	/*0x000*/     ULONG32      Owner : 1;            // 2 BitPosition                  
	/*0x000*/     ULONG32      WriteThrough : 1;     // 3 BitPosition                  
	/*0x000*/     ULONG32      CacheDisable : 1;     // 4 BitPosition                  
	/*0x000*/     ULONG32      Protection : 5;       // 5 BitPosition                  
	/*0x000*/     ULONG32      Prototype : 1;        // 10 BitPosition                 
	/*0x000*/     ULONG32      Transition : 1;       // 11 BitPosition                 
	/*0x000*/     ULONG32      PageFrameNumber : 20; // 12 BitPosition                 
}MMPTE_TRANSITION, *PMMPTE_TRANSITION;

typedef struct _MMPTE_SUBSECTION             // 6 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Valid : 1;                  // 0 BitPosition                  
	/*0x000*/     ULONG32      SubsectionAddressLow : 4;   // 1 BitPosition                  
	/*0x000*/     ULONG32      Protection : 5;             // 5 BitPosition                  
	/*0x000*/     ULONG32      Prototype : 1;              // 10 BitPosition                 
	/*0x000*/     ULONG32      SubsectionAddressHigh : 20; // 11 BitPosition                 
	/*0x000*/     ULONG32      WhichPool : 1;              // 31 BitPosition                 
}MMPTE_SUBSECTION, *PMMPTE_SUBSECTION;

typedef struct _MMPTE_LIST       // 6 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Valid : 1;      // 0 BitPosition                  
	/*0x000*/     ULONG32      OneEntry : 1;   // 1 BitPosition                  
	/*0x000*/     ULONG32      filler0 : 8;    // 2 BitPosition                  
	/*0x000*/     ULONG32      Prototype : 1;  // 10 BitPosition                 
	/*0x000*/     ULONG32      filler1 : 1;    // 11 BitPosition                 
	/*0x000*/     ULONG32      NextEntry : 20; // 12 BitPosition                 
}MMPTE_LIST, *PMMPTE_LIST;

typedef struct _MMPTE                     // 1 elements, 0x4 bytes (sizeof)  
{
	union                                 // 8 elements, 0x4 bytes (sizeof)  
	{
		/*0x000*/         ULONG32      Long;
		/*0x000*/         struct _MMPTE_HARDWARE Hard;      // 13 elements, 0x4 bytes (sizeof) 
		/*0x000*/         struct _HARDWARE_PTE Flush;       // 13 elements, 0x4 bytes (sizeof) 
		/*0x000*/         struct _MMPTE_PROTOTYPE Proto;    // 6 elements, 0x4 bytes (sizeof)  
		/*0x000*/         struct _MMPTE_SOFTWARE Soft;      // 6 elements, 0x4 bytes (sizeof)  
		/*0x000*/         struct _MMPTE_TRANSITION Trans;   // 9 elements, 0x4 bytes (sizeof)  
		/*0x000*/         struct _MMPTE_SUBSECTION Subsect; // 6 elements, 0x4 bytes (sizeof)  
		/*0x000*/         struct _MMPTE_LIST List;          // 6 elements, 0x4 bytes (sizeof)  
	}u;
}MMPTE, *PMMPTE;

typedef struct _CONTROL_AREA                   // 13 elements, 0x30 bytes (sizeof) 
{
	/*0x000*/     struct _SEGMENT* Segment;
	/*0x004*/     struct _LIST_ENTRY DereferenceList;        // 2 elements, 0x8 bytes (sizeof)   
	/*0x00C*/     ULONG32      NumberOfSectionReferences;
	/*0x010*/     ULONG32      NumberOfPfnReferences;
	/*0x014*/     ULONG32      NumberOfMappedViews;
	/*0x018*/     UINT16       NumberOfSubsections;
	/*0x01A*/     UINT16       FlushInProgressCount;
	/*0x01C*/     ULONG32      NumberOfUserReferences;
	union                                      // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x020*/         ULONG32      LongFlags;
		/*0x020*/         struct _MMSECTION_FLAGS Flags;         // 31 elements, 0x4 bytes (sizeof)  
	}u;
	/*0x024*/     struct _FILE_OBJECT* FilePointer;
	/*0x028*/     struct _EVENT_COUNTER* WaitingForDeletion;
	/*0x02C*/     UINT16       ModifiedWriteCount;
	/*0x02E*/     UINT16       NumberOfSystemCacheViews;
}CONTROL_AREA, *PCONTROL_AREA;

typedef struct _SEGMENT                                      // 14 elements, 0x40 bytes (sizeof) 
{
	/*0x000*/     struct _CONTROL_AREA* ControlArea;
	/*0x004*/     ULONG32      TotalNumberOfPtes;
	/*0x008*/     ULONG32      NonExtendedPtes;
	/*0x00C*/     ULONG32      WritableUserReferences;
	/*0x010*/     UINT64       SizeOfSegment;
	/*0x018*/     struct _MMPTE SegmentPteTemplate;                        // 1 elements, 0x4 bytes (sizeof)   
	/*0x01C*/     ULONG32      NumberOfCommittedPages;
	/*0x020*/     struct _MMEXTEND_INFO* ExtendInfo;
	/*0x024*/     VOID*        SystemImageBase;
	/*0x028*/     VOID*        BasedAddress;
	union                                                    // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x02C*/         ULONG32      ImageCommitment;
		/*0x02C*/         struct _EPROCESS* CreatingProcess;
	}u1;
	union                                                    // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x030*/         struct _SECTION_IMAGE_INFORMATION* ImageInformation;
		/*0x030*/         VOID*        FirstMappedVa;
	}u2;
	/*0x034*/     struct _MMPTE* PrototypePte;
	/*0x038*/     struct _MMPTE ThePtes[1];
	/*0x03C*/     UINT8        _PADDING0_[0x4];
}SEGMENT, *PSEGMENT;



typedef ULONG MM_PROTECTION_MASK;
typedef struct _SECTION {
	MMADDRESS_NODE Address;
	PSEGMENT Segment;
	LARGE_INTEGER SizeOfSection;
	union {
		ULONG LongFlags;
		MMSECTION_FLAGS Flags;
	} u;
	MM_PROTECTION_MASK InitialPageProtection;
} SECTION, *PSECTION;

VOID
FASTCALL
KeAcquireInStackQueuedSpinLockRaiseToSynch(
__inout PKSPIN_LOCK SpinLock,
__out PKLOCK_QUEUE_HANDLE LockHandle
);

KIRQL FASTCALL KeAcquireQueuedSpinLockRaiseToSynch(__in KSPIN_LOCK_QUEUE_NUMBER Number);

VOID FASTCALL KeReleaseInStackQueuedSpinLock(__in PKLOCK_QUEUE_HANDLE LockHandle);


typedef struct _DESCRIPTOR // 3 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     UINT16       Pad;
	/*0x002*/     UINT16       Limit;
	/*0x004*/     ULONG32      Base;
}DESCRIPTOR, *PDESCRIPTOR;

typedef struct _KSPECIAL_REGISTERS // 15 elements, 0x54 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Cr0;
	/*0x004*/     ULONG32      Cr2;
	/*0x008*/     ULONG32      Cr3;
	/*0x00C*/     ULONG32      Cr4;
	/*0x010*/     ULONG32      KernelDr0;
	/*0x014*/     ULONG32      KernelDr1;
	/*0x018*/     ULONG32      KernelDr2;
	/*0x01C*/     ULONG32      KernelDr3;
	/*0x020*/     ULONG32      KernelDr6;
	/*0x024*/     ULONG32      KernelDr7;
	/*0x028*/     struct _DESCRIPTOR Gdtr;       // 3 elements, 0x8 bytes (sizeof)   
	/*0x030*/     struct _DESCRIPTOR Idtr;       // 3 elements, 0x8 bytes (sizeof)   
	/*0x038*/     UINT16       Tr;
	/*0x03A*/     UINT16       Ldtr;
	/*0x03C*/     ULONG32      Reserved[6];
}KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;

typedef struct _KPROCESSOR_STATE                 // 2 elements, 0x320 bytes (sizeof)  
{
	/*0x000*/     struct _CONTEXT ContextFrame;                // 25 elements, 0x2CC bytes (sizeof) 
	/*0x2CC*/     struct _KSPECIAL_REGISTERS SpecialRegisters; // 15 elements, 0x54 bytes (sizeof)  
}KPROCESSOR_STATE, *PKPROCESSOR_STATE;

typedef struct _PP_LOOKASIDE_LIST // 2 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     struct _GENERAL_LOOKASIDE* P;
	/*0x004*/     struct _GENERAL_LOOKASIDE* L;
}PP_LOOKASIDE_LIST, *PPP_LOOKASIDE_LIST;

typedef VOID(NTAPI FUNCT_00BC_028D_WorkerRoutine) (VOID*, VOID*, VOID*, VOID*);

typedef struct _FNSAVE_FORMAT      // 8 elements, 0x6C bytes (sizeof) 
{
	/*0x000*/     ULONG32      ControlWord;
	/*0x004*/     ULONG32      StatusWord;
	/*0x008*/     ULONG32      TagWord;
	/*0x00C*/     ULONG32      ErrorOffset;
	/*0x010*/     ULONG32      ErrorSelector;
	/*0x014*/     ULONG32      DataOffset;
	/*0x018*/     ULONG32      DataSelector;
	/*0x01C*/     UINT8        RegisterArea[80];
}FNSAVE_FORMAT, *PFNSAVE_FORMAT;


typedef struct _FXSAVE_FORMAT       // 14 elements, 0x208 bytes (sizeof) 
{
	/*0x000*/     UINT16       ControlWord;
	/*0x002*/     UINT16       StatusWord;
	/*0x004*/     UINT16       TagWord;
	/*0x006*/     UINT16       ErrorOpcode;
	/*0x008*/     ULONG32      ErrorOffset;
	/*0x00C*/     ULONG32      ErrorSelector;
	/*0x010*/     ULONG32      DataOffset;
	/*0x014*/     ULONG32      DataSelector;
	/*0x018*/     ULONG32      MXCsr;
	/*0x01C*/     ULONG32      MXCsrMask;
	/*0x020*/     UINT8        RegisterArea[128];
	/*0x0A0*/     UINT8        Reserved3[128];
	/*0x120*/     UINT8        Reserved4[224];
	/*0x200*/     UINT8        Align16Byte[8];
}FXSAVE_FORMAT, *PFXSAVE_FORMAT;

typedef struct _FX_SAVE_AREA          // 3 elements, 0x210 bytes (sizeof)  
{
	union                             // 2 elements, 0x208 bytes (sizeof)  
	{
		/*0x000*/         struct _FNSAVE_FORMAT FnArea; // 8 elements, 0x6C bytes (sizeof)   
		/*0x000*/         struct _FXSAVE_FORMAT FxArea; // 14 elements, 0x208 bytes (sizeof) 
	}U;
	/*0x208*/     ULONG32      NpxSavedCpu;
	/*0x20C*/     ULONG32      Cr0NpxState;
}FX_SAVE_AREA, *PFX_SAVE_AREA;



typedef struct _PROCESSOR_IDLE_TIMES     // 3 elements, 0x20 bytes (sizeof) 
{
	/*0x000*/     UINT64       StartTime;
	/*0x008*/     UINT64       EndTime;
	/*0x010*/     ULONG32      IdleHandlerReserved[4];
}PROCESSOR_IDLE_TIMES, *PPROCESSOR_IDLE_TIMES;

typedef LONG32(FASTCALL FUNCT_0049_0301_PerfSetThrottle) (UINT8);

typedef VOID(FASTCALL FUNCT_00BC_02E9_IdleFunction) (struct _PROCESSOR_POWER_STATE*);

typedef struct _PROCESSOR_POWER_STATE                 // 45 elements, 0x120 bytes (sizeof) 
{
	/*0x000*/     FUNCT_00BC_02E9_IdleFunction* IdleFunction;
	/*0x004*/     ULONG32      Idle0KernelTimeLimit;
	/*0x008*/     ULONG32      Idle0LastTime;
	/*0x00C*/     VOID*        IdleHandlers;
	/*0x010*/     VOID*        IdleState;
	/*0x014*/     ULONG32      IdleHandlersCount;
	/*0x018*/     UINT64       LastCheck;
	/*0x020*/     struct _PROCESSOR_IDLE_TIMES IdleTimes;           // 3 elements, 0x20 bytes (sizeof)   
	/*0x040*/     ULONG32      IdleTime1;
	/*0x044*/     ULONG32      PromotionCheck;
	/*0x048*/     ULONG32      IdleTime2;
	/*0x04C*/     UINT8        CurrentThrottle;
	/*0x04D*/     UINT8        ThermalThrottleLimit;
	/*0x04E*/     UINT8        CurrentThrottleIndex;
	/*0x04F*/     UINT8        ThermalThrottleIndex;
	/*0x050*/     ULONG32      LastKernelUserTime;
	/*0x054*/     ULONG32      LastIdleThreadKernelTime;
	/*0x058*/     ULONG32      PackageIdleStartTime;
	/*0x05C*/     ULONG32      PackageIdleTime;
	/*0x060*/     ULONG32      DebugCount;
	/*0x064*/     ULONG32      LastSysTime;
	/*0x068*/     UINT64       TotalIdleStateTime[3];
	/*0x080*/     ULONG32      TotalIdleTransitions[3];
	/*0x08C*/     UINT8        _PADDING0_[0x4];
	/*0x090*/     UINT64       PreviousC3StateTime;
	/*0x098*/     UINT8        KneeThrottleIndex;
	/*0x099*/     UINT8        ThrottleLimitIndex;
	/*0x09A*/     UINT8        PerfStatesCount;
	/*0x09B*/     UINT8        ProcessorMinThrottle;
	/*0x09C*/     UINT8        ProcessorMaxThrottle;
	/*0x09D*/     UINT8        EnableIdleAccounting;
	/*0x09E*/     UINT8        LastC3Percentage;
	/*0x09F*/     UINT8        LastAdjustedBusyPercentage;
	/*0x0A0*/     ULONG32      PromotionCount;
	/*0x0A4*/     ULONG32      DemotionCount;
	/*0x0A8*/     ULONG32      ErrorCount;
	/*0x0AC*/     ULONG32      RetryCount;
	/*0x0B0*/     ULONG32      Flags;
	/*0x0B4*/     UINT8        _PADDING1_[0x4];
	/*0x0B8*/     union _LARGE_INTEGER PerfCounterFrequency;        // 4 elements, 0x8 bytes (sizeof)    
	/*0x0C0*/     ULONG32      PerfTickCount;
	/*0x0C4*/     UINT8        _PADDING2_[0x4];
	/*0x0C8*/     struct _KTIMER PerfTimer;                         // 5 elements, 0x28 bytes (sizeof)   
	/*0x0F0*/     struct _KDPC PerfDpc;                             // 9 elements, 0x20 bytes (sizeof)   
	/*0x110*/     struct _PROCESSOR_PERF_STATE* PerfStates;
	/*0x114*/     FUNCT_0049_0301_PerfSetThrottle* PerfSetThrottle;
	/*0x118*/     ULONG32      LastC3KernelUserTime;
	/*0x11C*/     ULONG32      LastPackageIdleTime;
}PROCESSOR_POWER_STATE, *PPROCESSOR_POWER_STATE;




typedef struct _KPRCB                                    // 91 elements, 0xC50 bytes (sizeof) 
{
	/*0x000*/     UINT16       MinorVersion;
	/*0x002*/     UINT16       MajorVersion;
	/*0x004*/     struct _KTHREAD* CurrentThread;
	/*0x008*/     struct _KTHREAD* NextThread;
	/*0x00C*/     struct _KTHREAD* IdleThread;
	/*0x010*/     CHAR         Number;
	/*0x011*/     CHAR         Reserved;
	/*0x012*/     UINT16       BuildType;
	/*0x014*/     ULONG32      SetMember;
	/*0x018*/     CHAR         CpuType;
	/*0x019*/     CHAR         CpuID;
	/*0x01A*/     UINT16       CpuStep;
	/*0x01C*/     struct _KPROCESSOR_STATE ProcessorState;             // 2 elements, 0x320 bytes (sizeof)  
	/*0x33C*/     ULONG32      KernelReserved[16];
	/*0x37C*/     ULONG32      HalReserved[16];
	/*0x3BC*/     UINT8        PrcbPad0[92];
	/*0x418*/     struct _KSPIN_LOCK_QUEUE LockQueue[16];
	/*0x498*/     UINT8        PrcbPad1[8];
	/*0x4A0*/     struct _KTHREAD* NpxThread;
	/*0x4A4*/     ULONG32      InterruptCount;
	/*0x4A8*/     ULONG32      KernelTime;
	/*0x4AC*/     ULONG32      UserTime;
	/*0x4B0*/     ULONG32      DpcTime;
	/*0x4B4*/     ULONG32      DebugDpcTime;
	/*0x4B8*/     ULONG32      InterruptTime;
	/*0x4BC*/     ULONG32      AdjustDpcThreshold;
	/*0x4C0*/     ULONG32      PageColor;
	/*0x4C4*/     ULONG32      SkipTick;
	/*0x4C8*/     UINT8        MultiThreadSetBusy;
	/*0x4C9*/     UINT8        Spare2[3];
	/*0x4CC*/     struct _KNODE* ParentNode;
	/*0x4D0*/     ULONG32      MultiThreadProcessorSet;
	/*0x4D4*/     struct _KPRCB* MultiThreadSetMaster;
	/*0x4D8*/     ULONG32      ThreadStartCount[2];
	/*0x4E0*/     ULONG32      CcFastReadNoWait;
	/*0x4E4*/     ULONG32      CcFastReadWait;
	/*0x4E8*/     ULONG32      CcFastReadNotPossible;
	/*0x4EC*/     ULONG32      CcCopyReadNoWait;
	/*0x4F0*/     ULONG32      CcCopyReadWait;
	/*0x4F4*/     ULONG32      CcCopyReadNoWaitMiss;
	/*0x4F8*/     ULONG32      KeAlignmentFixupCount;
	/*0x4FC*/     ULONG32      KeContextSwitches;
	/*0x500*/     ULONG32      KeDcacheFlushCount;
	/*0x504*/     ULONG32      KeExceptionDispatchCount;
	/*0x508*/     ULONG32      KeFirstLevelTbFills;
	/*0x50C*/     ULONG32      KeFloatingEmulationCount;
	/*0x510*/     ULONG32      KeIcacheFlushCount;
	/*0x514*/     ULONG32      KeSecondLevelTbFills;
	/*0x518*/     ULONG32      KeSystemCalls;
	/*0x51C*/     ULONG32      SpareCounter0[1];
	/*0x520*/     struct _PP_LOOKASIDE_LIST PPLookasideList[16];
	/*0x5A0*/     struct _PP_LOOKASIDE_LIST PPNPagedLookasideList[32];
	/*0x6A0*/     struct _PP_LOOKASIDE_LIST PPPagedLookasideList[32];
	/*0x7A0*/     ULONG32      PacketBarrier;
	/*0x7A4*/     ULONG32      ReverseStall;
	/*0x7A8*/     VOID*        IpiFrame;
	/*0x7AC*/     UINT8        PrcbPad2[52];
	/*0x7E0*/     VOID*        CurrentPacket[3];
	/*0x7EC*/     ULONG32      TargetSet;
	/*0x7F0*/     FUNCT_00BC_028D_WorkerRoutine* WorkerRoutine;
	/*0x7F4*/     ULONG32      IpiFrozen;
	/*0x7F8*/     UINT8        PrcbPad3[40];
	/*0x820*/     ULONG32      RequestSummary;
	/*0x824*/     struct _KPRCB* SignalDone;
	/*0x828*/     UINT8        PrcbPad4[56];
	/*0x860*/     struct _LIST_ENTRY DpcListHead;                      // 2 elements, 0x8 bytes (sizeof)    
	/*0x868*/     VOID*        DpcStack;
	/*0x86C*/     ULONG32      DpcCount;
	/*0x870*/     ULONG32      DpcQueueDepth;
	/*0x874*/     ULONG32      DpcRoutineActive;
	/*0x878*/     ULONG32      DpcInterruptRequested;
	/*0x87C*/     ULONG32      DpcLastCount;
	/*0x880*/     ULONG32      DpcRequestRate;
	/*0x884*/     ULONG32      MaximumDpcQueueDepth;
	/*0x888*/     ULONG32      MinimumDpcRate;
	/*0x88C*/     ULONG32      QuantumEnd;
	/*0x890*/     UINT8        PrcbPad5[16];
	/*0x8A0*/     ULONG32      DpcLock;
	/*0x8A4*/     UINT8        PrcbPad6[28];
	/*0x8C0*/     struct _KDPC CallDpc;                                // 9 elements, 0x20 bytes (sizeof)   
	/*0x8E0*/     VOID*        ChainedInterruptList;
	/*0x8E4*/     LONG32       LookasideIrpFloat;
	/*0x8E8*/     ULONG32      SpareFields0[6];
	/*0x900*/     UINT8        VendorString[13];
	/*0x90D*/     UINT8        InitialApicId;
	/*0x90E*/     UINT8        LogicalProcessorsPerPhysicalProcessor;
	/*0x90F*/     UINT8        _PADDING0_[0x1];
	/*0x910*/     ULONG32      MHz;
	/*0x914*/     ULONG32      FeatureBits;
	/*0x918*/     union _LARGE_INTEGER UpdateSignature;                // 4 elements, 0x8 bytes (sizeof)    
	/*0x920*/     struct _FX_SAVE_AREA NpxSaveArea;                    // 3 elements, 0x210 bytes (sizeof)  
	/*0xB30*/     struct _PROCESSOR_POWER_STATE PowerState;            // 45 elements, 0x120 bytes (sizeof) 
}KPRCB, *PKPRCB;

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	PULONG_PTR Base;
	PULONG Count;
	ULONG Limit;
	PUCHAR Number;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;