#pragma once
#include <ntifs.h>
#include <ntdef.h>
#include <ntimage.h>


#define DRIVER_PREFIX "InjDriver: "
#define EDR_MEMORY_TAG ' rdE'
#define PROCESS_INFO_MEMORY_TAG ' crP'
#define DbgPrintx(s,...) DbgPrint(DRIVER_PREFIX  s "\n",__VA_ARGS__)
#define DbgPrintLine(s,...) DbgPrint(DRIVER_PREFIX "[%s]" s "\n",__FUNCTION__ ,__VA_ARGS__)
#define DbgError(s,...) DbgPrintLine("<Error>" s , __VA_ARGS__)
#define DbgInfo(s,...) DbgPrintLine("<Info>" s , __VA_ARGS__)

#define DLL_PATH64 L"C:\\Windows\\System32\\HookDllx64.dll"
#define DLL_PATH86 L"C:\\Windows\\System32\\HookDllx86.dll"

// Process structure to hold information about loaded images and state
typedef struct _PROCESS_INFO {

    LIST_ENTRY ListEntry;

    HANDLE ProcessId;
    BOOLEAN IsInjected = FALSE;
    BOOLEAN ForceUserApc;
    ULONG LoadedDlls;
    PVOID LdrLoadDllAddress = NULL;
    PUNICODE_STRING DllPath;

} PROCESS_INFO, * PPROCESS_INFO;


typedef enum _SYSTEM_DLL
{
    NOTHING_LOADED = 0x0000,
    SYSTEM32_NTDLL_LOADED = 0x0001,
    SYSTEM32_KERNEL32_LOADED = 0x0002,
    SYSWOW64_NTDLL_LOADED = 0x0004,
    SYSTEM32_WOW64_LOADED = 0x0008,
    SYSTEM32_WOW64WIN_LOADED = 0x0010,
    SYSTEM32_WOW64CPU_LOADED = 0x0020,
    SYSTEM32_WOWARMHW_LOADED = 0x0040,
} SYSTEM_DLL, *PSYSTEM_DLL;

typedef struct _SYSTEM_DLL_DESCRIPTOR
{
    UNICODE_STRING  DllPath;
    SYSTEM_DLL  Flag;
} SYSTEM_DLL_DESCRIPTOR, * PSYSTEM_DLL_DESCRIPTOR;

SYSTEM_DLL_DESCRIPTOR g_pSystemDlls[] = {
  { RTL_CONSTANT_STRING(L"\\SysWow64\\ntdll.dll"),    SYSWOW64_NTDLL_LOADED    },
  { RTL_CONSTANT_STRING(L"\\System32\\ntdll.dll"),    SYSTEM32_NTDLL_LOADED    },
  { RTL_CONSTANT_STRING(L"\\System32\\kernel32.dll"), SYSTEM32_KERNEL32_LOADED },
  { RTL_CONSTANT_STRING(L"\\System32\\wow64.dll"),    SYSTEM32_WOW64_LOADED    },
  { RTL_CONSTANT_STRING(L"\\System32\\wow64win.dll"), SYSTEM32_WOW64WIN_LOADED },
  { RTL_CONSTANT_STRING(L"\\System32\\wow64cpu.dll"), SYSTEM32_WOW64CPU_LOADED },
};


VOID DriverUnload(PDRIVER_OBJECT DriverObject);
VOID DriverInitialize();

BOOLEAN AreAllDllsLoaded(PPROCESS_INFO ProcessInfo);

// Process creation callback
VOID ProcessCreateNotifyCallback(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create);

VOID ImageLoadNotifyCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo);



PPROCESS_INFO FindProcessInfo(HANDLE ProcessId);
VOID AddProcess(HANDLE ProcessId);
VOID RemoveProcess(HANDLE ProcessId);


////////////////////////////////////////////////////////
///                                                  ///
///                                                  ///
///             API Function for processes           ///
///                                                  ///
///                                                  ///
//////////////////////////////////////////////////////// 

extern "C"
NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(
    _In_ PEPROCESS Process
);

extern "C"
NTKERNELAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);

extern "C"
NTKERNELAPI
BOOLEAN
NTAPI
PsIsProtectedProcess(
    _In_ PEPROCESS Process
);

extern "C"
NTKERNELAPI
USHORT
NTAPI
PsWow64GetProcessMachine(
    _In_ PEPROCESS Process
);


////////////////////////////////////////////////////////
///                                                  ///
///                                                  ///
///         Function address resolution              ///
///                                                  ///
///                                                  ///
//////////////////////////////////////////////////////// 

PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID DllBase,
    _In_ PANSI_STRING ExportName
);

extern "C"
NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
    _In_ PVOID BaseOfImage,
    _In_ BOOLEAN MappedAsImage,
    _In_ USHORT DirectoryEntry,
    _Out_ PULONG Size
);

////////////////////////////////////////////////////////
///                                                  ///
///                                                  ///
///                 APC Related code                 ///
///                                                  ///
///                                                  ///
////////////////////////////////////////////////////////
extern "C"
typedef enum _KAPC_ENVIRONMENT
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

extern "C"
typedef
VOID
(NTAPI* PKNORMAL_ROUTINE)(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
    );

extern "C"
typedef
VOID
(NTAPI* PKKERNEL_ROUTINE)(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
    );

extern "C"
typedef
VOID
(NTAPI* PKRUNDOWN_ROUTINE) (
    _In_ PKAPC Apc
    );

NTSTATUS
NTAPI
QueueInjectionApc(
    _In_ KPROCESSOR_MODE ApcMode,
    _In_ PKNORMAL_ROUTINE NormalRoutine,
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
);

extern "C"
NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
    _Out_ PRKAPC Apc,
    _In_ PETHREAD Thread,
    _In_ KAPC_ENVIRONMENT Environment,
    _In_ PKKERNEL_ROUTINE KernelRoutine,
    _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
    _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
    _In_opt_ KPROCESSOR_MODE ApcMode,
    _In_opt_ PVOID NormalContext
);

extern "C"
NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
    _Inout_ PRKAPC Apc,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_ KPRIORITY Increment
);

VOID
NTAPI
InjectionApcKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
);

VOID
NTAPI
InjectionApcNormalRoutine(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
);

NTSTATUS
NTAPI
EdrInject(
    _In_ PPROCESS_INFO pProcessInfo
);

extern "C"
BOOLEAN
NTAPI
KeTestAlertThread(
    _In_ KPROCESSOR_MODE AlertMode
);