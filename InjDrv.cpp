#include "InjDrv.h"

#pragma warning(disable : 4996)
#pragma warning(disable : 4703)
#pragma warning(disable : 4701)
#pragma warning(disable : 4533)

#define DLL_PATH64 L"C:\\Windows\\System32\\HookDllx64.dll"
#define DLL_PATH86 L"C:\\Windows\\System32\\HookDllx86.dll"
ANSI_STRING LdrLoadDllRoutineName = RTL_CONSTANT_STRING("LdrLoadDll");

LIST_ENTRY ProcessList;
FAST_MUTEX ProcessListLock;
UNICODE_STRING g_DllPath64;
UNICODE_STRING g_DllPath86;

static BOOLEAN gRegisteredForProcessCreation = FALSE;
static BOOLEAN gRegisteredForThreadCreation = FALSE;
static BOOLEAN gRegisteredForImageLoad = FALSE;

extern "C"
// Register callbacks when the driver is loaded
NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrintx("Driver load (0x%p, %wZ)", DriverObject, RegistryPath);


    NTSTATUS status = STATUS_SUCCESS;
    do {

        status = PsSetCreateProcessNotifyRoutine(ProcessCreateNotifyCallback, FALSE);
        if (!NT_SUCCESS(status))
        {
            DbgPrintx("Failed to register process creation routine");
            break;
        }
        gRegisteredForProcessCreation = TRUE;

        status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageLoadNotifyCallback);
        if (!NT_SUCCESS(status))
        {
            DbgPrintx("Failed to register image load routine");
            PsSetCreateProcessNotifyRoutine(ProcessCreateNotifyCallback, TRUE);
            break;
        }
        gRegisteredForImageLoad = TRUE;

    } while (false);

    if (!NT_SUCCESS(status))
    {
        DbgPrintx("Failed to start driver");
        return status;
    }

    DriverInitialize();
    DriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}

// Unregister callbacks when the driver is unloaded
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {

    UNREFERENCED_PARAMETER(DriverObject);

    PsSetCreateProcessNotifyRoutine(ProcessCreateNotifyCallback, TRUE);
    PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageLoadNotifyCallback);

    // Cleanup process list
    ExAcquireFastMutex(&ProcessListLock);
    PLIST_ENTRY entry, nextEntry;
    for (entry = ProcessList.Flink; entry != &ProcessList; entry = nextEntry) {
        nextEntry = entry->Flink;
        RemoveProcess(CONTAINING_RECORD(entry, PROCESS_INFO, ListEntry)->ProcessId);
    }
    ExReleaseFastMutex(&ProcessListLock);
}

// Initialize the process list and lock
VOID DriverInitialize() {
    InitializeListHead(&ProcessList);
    ExInitializeFastMutex(&ProcessListLock);
    RtlInitUnicodeString(&g_DllPath64, DLL_PATH64);
    RtlInitUnicodeString(&g_DllPath86, DLL_PATH86);
}


////////////////////////////////////////////////////////
///                                                  ///
///                                                  ///
///                 Notify Callback                  ///
///                                                  ///
///                                                  ///
//////////////////////////////////////////////////////// 

// Process creation callback
VOID ProcessCreateNotifyCallback(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentId);

    ExAcquireFastMutex(&ProcessListLock);
    if (Create) {
        AddProcess(ProcessId);  // Add the process to the list
    }
    else {
        RemoveProcess(ProcessId);  // Remove it when the process terminates
    }
    ExReleaseFastMutex(&ProcessListLock);
}

BOOLEAN IsSuffixMatch(const CHAR* imageName, const CHAR* suffix) {
    if (imageName == NULL || suffix == NULL) return FALSE;

    size_t imageNameLen = strlen(imageName);
    size_t suffixLen = strlen(suffix);

    // Check if the suffix is longer than the image name.
    if (suffixLen > imageNameLen) {
        return FALSE;
    }

    // Compare the end of imageName with suffix
    return _strnicmp(imageName + imageNameLen - suffixLen, suffix, suffixLen) == 0;
}

// Image load callback
VOID ImageLoadNotifyCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo)
{

    ExAcquireFastMutex(&ProcessListLock);
    PPROCESS_INFO ProcessInfo = FindProcessInfo(ProcessId);

    DbgInfo("Loading image %wZ\nfor: [PID: %u, Name: '%s']", FullImageName, HandleToUlong(ProcessId), PsGetProcessImageFileName(PsGetCurrentProcess()));

    if (!ProcessInfo)
    {
        DbgError("Could not find process: [PID: %u, Name: '%wZ'] In image load callback routine", HandleToUlong(ProcessId), PsGetProcessImageFileName(PsGetCurrentProcess()));
        ExReleaseFastMutex(&ProcessListLock);
        return;
    }

    if (ProcessInfo->IsInjected)
    {
        DbgInfo("Already injected to process: [PID: %u, Name: '%s']", HandleToUlong(ProcessId), PsGetProcessImageFileName(PsGetCurrentProcess()));
        ExReleaseFastMutex(&ProcessListLock);
        return;
    }

    if (PsIsProtectedProcess(PsGetCurrentProcess()))
    {
        DbgInfo("Its protected process [PID: %u, Name: '%s'] wont inject at this point", HandleToUlong(ProcessId), PsGetProcessImageFileName(PsGetCurrentProcess()));
        ExReleaseFastMutex(&ProcessListLock);
        return;
    }
    else {
        DbgInfo("Found process: %s", PsGetProcessImageFileName(PsGetCurrentProcess()));
    }


    // If all necessary DLLs are loaded, perform the APC injection
    if (AreAllDllsLoaded(ProcessInfo)) {
        // All necessary dlls are loaded
        ProcessInfo->IsInjected = TRUE;
        DbgInfo("All necessary dlls are loaded for process [PID:%u, Name: '%s', Wow64: %s], will queue apc injection ",
            HandleToUlong(ProcessId),
            PsGetProcessImageFileName(PsGetCurrentProcess()),
            PsGetProcessWow64Process(PsGetCurrentProcess()) ? "True" : "False");

        QueueInjectionApc(KernelMode,
            (PKNORMAL_ROUTINE)&InjectionApcNormalRoutine,
            ProcessInfo,
            NULL,
            NULL);

        ExReleaseFastMutex(&ProcessListLock);
        return;
    }
    
    // Not all necessary dlls are loaded
    for (ULONG Index = 0; Index < RTL_NUMBER_OF(g_pSystemDlls); Index++)
    {
        PUNICODE_STRING pSysDllPath = &g_pSystemDlls[Index].DllPath;
        if (RtlSuffixUnicodeString(pSysDllPath, FullImageName, TRUE))
        {
            // The current dll is one of our essential dlls
            DbgInfo("The Process is loading essential image [PID: %u, Name: '%s' Iamge: '%wZ']",
                HandleToUlong(ProcessId),
                PsGetProcessImageFileName(PsGetCurrentProcess()),
                FullImageName);

            ProcessInfo->LoadedDlls |= g_pSystemDlls[Index].Flag;
            
            if (g_pSystemDlls[Index].Flag == SYSTEM32_NTDLL_LOADED)
            {
                // Its the native ntdll dll, we need to get the LdrLoadDll address
                ProcessInfo->LdrLoadDllAddress = RtlFindExportedRoutineByName(ImageInfo->ImageBase, &LdrLoadDllRoutineName);
            }

            // Found the dll so we can break the loop
            break;
        }
    }

    ExReleaseFastMutex(&ProcessListLock);
}

// Check if all required DLLs are loaded
BOOLEAN AreAllDllsLoaded(PPROCESS_INFO ProcessInfo) {
    
    // We want ntdll.dll to be loaded
    // as we are only injecting at this point to x64
    // we can do it thunkless so we dont mind of dlls
    // for ARM or x86
    // We also want kernel32.dll to be loaded because our injected dll uses it.
    ULONG RequiredDlls = SYSTEM32_NTDLL_LOADED | SYSTEM32_KERNEL32_LOADED;
    
#if defined (_M_AMD64)
    if (PsGetProcessWow64Process(PsGetCurrentProcess()))
    {
        // Add to the required dlls the wow64 related dlls
        RequiredDlls |= SYSTEM32_WOW64CPU_LOADED;
        RequiredDlls |= SYSWOW64_NTDLL_LOADED;
    }
#endif

    BOOLEAN Ret = (ProcessInfo->LoadedDlls & RequiredDlls) == RequiredDlls;

    return Ret;

}

////////////////////////////////////////////////////////
///                                                  ///
///                                                  ///
///                 List related code                ///
///                                                  ///
///                                                  ///
//////////////////////////////////////////////////////// 

// Find process information by process ID
PPROCESS_INFO FindProcessInfo(HANDLE ProcessId) {
    PLIST_ENTRY entry;
    for (entry = ProcessList.Flink; entry != &ProcessList; entry = entry->Flink) {
        PPROCESS_INFO ProcessInfo = CONTAINING_RECORD(entry, PROCESS_INFO, ListEntry);
        if (ProcessInfo->ProcessId == ProcessId) {
            return ProcessInfo;
        }
    }
    return NULL;
}

// Add a process to the process list
VOID AddProcess(HANDLE ProcessId) {
    PPROCESS_INFO ProcessInfo = (PPROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_INFO), PROCESS_INFO_MEMORY_TAG);
    RtlZeroMemory(ProcessInfo, sizeof(PROCESS_INFO));
    ProcessInfo->ProcessId = ProcessId;
    ProcessInfo->ForceUserApc = TRUE;
    InsertTailList(&ProcessList, &ProcessInfo->ListEntry);
}

// Remove a process from the process list
VOID RemoveProcess(HANDLE ProcessId) {
    PPROCESS_INFO ProcessInfo = FindProcessInfo(ProcessId);
    if (ProcessInfo) {
        RemoveEntryList(&ProcessInfo->ListEntry);
        ExFreePoolWithTag(ProcessInfo, PROCESS_INFO_MEMORY_TAG);
    }
}

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
)
{
    PULONG NameTable;
    PUSHORT OrdinalTable;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
    ULONG Index;
    USHORT Ordinal;
    PVOID Function;
    ULONG ExportSize;
    PULONG ExportTable;
    LONG Ret;
    BOOLEAN Found = FALSE;

    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(DllBase,
        TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportSize);

    if (!ExportDirectory)
    {
        DbgError("RtlImageDirectoryEntryToData:: Failed to find ExportDirectory");
        return NULL;
    }

    NameTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNames);
    OrdinalTable = ((PUSHORT)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNameOrdinals));

    Index = 0;

    while (Index < ExportDirectory->NumberOfNames)
    {
        Ret = strcmp(ExportName->Buffer, (PCHAR)DllBase + NameTable[Index]);
        if (Ret == 0)
        {
            Found = TRUE;
            break;
        }
        Index++;
    }

    if (!Found)
    {
        DbgError("Could not find the function in export directory: %Z", ExportName);
        return NULL;
    }

    Ordinal = OrdinalTable[Index];

    if (Ordinal < 0 || Ordinal >= ExportDirectory->NumberOfFunctions)
    {
        DbgError("Ordinal out of bound for function: %Z", ExportName);
        return NULL;
    }

    ExportTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfFunctions);
    Function = (PVOID)((ULONG_PTR)DllBase + ExportTable[Ordinal]);
    DbgInfo("Found LdrLoadDll at 0x%p", Function);
    return Function;
}


////////////////////////////////////////////////////////
///                                                  ///
///                                                  ///
///                 APC Related code                 ///
///                                                  ///
///                                                  ///
//////////////////////////////////////////////////////// 


NTSTATUS
NTAPI
QueueInjectionApc(
    _In_ KPROCESSOR_MODE ApcMode,
    _In_ PKNORMAL_ROUTINE NormalRoutine,
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PETHREAD pThread = PsGetCurrentThread();
    HANDLE ThreadId = PsGetThreadId(pThread);
    HANDLE ProcessId = PsGetThreadProcessId(pThread);

    // Allocate memory for the KAPC
    PKAPC Apc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool,
                                            sizeof(KAPC),
                                            EDR_MEMORY_TAG);
    if (!Apc)
    {
        DbgError("ExAllocatePoolWithTag:: Failed to allocate Apc ([P:T] :: [%u:%u])", HandleToUlong(ProcessId), HandleToUlong(ThreadId));
        Status = STATUS_INSUFFICIENT_RESOURCES;
        return Status;
    }

    // Initialize the Apc
    KeInitializeApc(Apc,
                    pThread,
                    OriginalApcEnvironment,
                    &InjectionApcKernelRoutine,
                    NULL,
                    NormalRoutine,
                    ApcMode,
                    NormalContext);

    BOOLEAN Inserted = KeInsertQueueApc(Apc,              // Apc
                                        SystemArgument1,  // SystemArgument1
                                        SystemArgument2,  // SystemArgument2
                                        0);

    if (!Inserted)
    {
        DbgError("KeInsertQueueApc:: Failed inserting Apc ([P:T] :: [%u:%u])", HandleToUlong(ProcessId), HandleToUlong(ThreadId));
        ExFreePoolWithTag(Apc, EDR_MEMORY_TAG);
        return STATUS_UNSUCCESSFUL;
    }

    DbgInfo("Inserted injection APC for process [PID: %u, Name: '%s'] ", HandleToUlong(ProcessId), PsGetProcessImageFileName(PsGetCurrentProcess()));

    return Status;
}


VOID
NTAPI
InjectionApcNormalRoutine(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
)
{
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    PPROCESS_INFO InjectionContext = (PPROCESS_INFO)NormalContext;
    EdrInject(InjectionContext);
}

NTSTATUS
NTAPI
EdrInject(
    _In_ PPROCESS_INFO pProcessInfo
)
{
    NTSTATUS Status;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
        NULL,
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    HANDLE hSection;
    SIZE_T SectionSize = PAGE_SIZE;
    LARGE_INTEGER MaximumSize;
    MaximumSize.QuadPart = SectionSize;

    Status = ZwCreateSection(&hSection,
        GENERIC_READ | GENERIC_WRITE,
        &ObjectAttributes,
        &MaximumSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL);

    if (!NT_SUCCESS(Status))
    {
        DbgError("ZwCreateSection:: Failed to create section for process: %u", HandleToUlong(pProcessInfo->ProcessId));
        goto End;
    }

    // Map the section
    PVOID SectionMemoryAddress = NULL;
    Status = ZwMapViewOfSection(hSection,
        ZwCurrentProcess(),
        &SectionMemoryAddress,
        0,
        SectionSize,
        NULL,
        &SectionSize,
        ViewUnmap,
        0,
        PAGE_READWRITE);
    if (!NT_SUCCESS(Status))
    {
        DbgError("ZwMapViewOfSection:: Failed to map view of section for process: %u", HandleToUlong(pProcessInfo->ProcessId));
        goto End;
    }

    DbgInfo("Mapped section to process %u on address 0x%p", HandleToUlong(pProcessInfo->ProcessId), SectionMemoryAddress);

    // Fire an Apc of injection
    PUNICODE_STRING pDllPath = (PUNICODE_STRING)(SectionMemoryAddress);
    PWCHAR DllPathBuffer = (PWCHAR)((PUCHAR)pDllPath + sizeof(UNICODE_STRING));

    PUNICODE_STRING pSourcDll;
    if (PsGetProcessWow64Process(PsGetCurrentProcess()))
    {
        pSourcDll = &g_DllPath86;
    }
    else {
        pSourcDll = &g_DllPath64;
    }

    // Copy to the section
    RtlCopyMemory(DllPathBuffer,
        pSourcDll->Buffer,
        pSourcDll->Length+1);

    RtlInitUnicodeString(pDllPath, DllPathBuffer);

    Status = QueueInjectionApc(UserMode,
                                (PKNORMAL_ROUTINE)(ULONG_PTR)pProcessInfo->LdrLoadDllAddress,
                                NULL,    // Translates to 1st param. of LdrLoadDll (SearchPath)
                                NULL,    // Translates to 2nd param. of LdrLoadDll (DllCharacteristics)
                                pDllPath // Translates to 3rd param. of LdrLoadDll (DllName)
                            );
End:
    ZwClose(hSection);
    if (NT_SUCCESS(Status)/* && pProcessInfo->ForceUserApc*/)
    {
        DbgInfo("Inserted LdrLoadDll APC for process %u \nThe section start at 0x%p", HandleToUlong(pProcessInfo->ProcessId), SectionMemoryAddress);
        //KeTestAlertThread(UserMode); /*TODO: Find out why alerting resulting in apc not executing */
    }


    return Status;
}

VOID
NTAPI
InjectionApcKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    ExFreePoolWithTag(Apc, EDR_MEMORY_TAG);
}