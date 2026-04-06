#pragma comment(lib, "d3d11.lib")
#include <iostream>
#include <string>
#include <windows.h>
#include <chrono>
#include <cctype>
#include <ctype.h>
#include "asm.h"
#include <d3d11.h>
#include <tlhelp32.h>

using namespace std;

const BYTE expected[] = { 0x4C, 0x8B, 0xD1, 0xB8 };

INPUT clicks[2] = {};


// Enables SE_DEBUG_NAME privilege to gain access to processes owned by other users
bool EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

int main() {
    EnableDebugPrivilege();
    GetMyPeb();
    if (pebBase == 0) {
        printf("Ошибка: Не удалось получить PEB!\n");
        return 1;
    }
    
    // Retrieve NTDLL module base address by walking the PEB's module list
    NTDLL::ldr = *(uintptr_t*)(pebBase + 0x18);
    uintptr_t anchor = (NTDLL::ldr + 0x10);
    uintptr_t current = *(uintptr_t*)anchor;
    do {
        uintptr_t bufferAddress = *(uintptr_t*)(current + 0x60);
        if (bufferAddress != 0) {
            wchar_t* dllName = (wchar_t*)bufferAddress;
            if (_wcsicmp(dllName, L"ntdll.dll") == 0) {
                NTDLL::ntBase = *(uintptr_t*)(current + 0x30);
                break;
            }
        }
        current = *(uintptr_t*)current;
    } while (current != anchor);
    
    if (NTDLL::ntBase != 0) {
        printf("NTDLL Found at: %p\n", (void*)NTDLL::ntBase);
    }
    else {
        printf("NTDLL not found!\n");
    }
    
    // Verify NTDLL signature (MZ header)
    unsigned short target = *(unsigned short*)NTDLL::ntBase;
    if (target == 0x5A4D) {
        printf("Signature confirmed: MZ is here!\n");
    }
    else {
        printf("????\n");
    }
    
    // Resolve native API function addresses using hash-based lookup
    uintptr_t ntOpen = GetFunctionAddress(0x3F4DD136);
    uintptr_t pNtRead = GetFunctionAddress(0x307C3661);
    uintptr_t pNtWrite = GetFunctionAddress(0xFAE162D0);

    uintptr_t pNtSysInfo = GetFunctionAddress(0x684921E6);
    uintptr_t pNtCreateThreadEx = GetFunctionAddress(0xFE3E696E);
    uintptr_t pNtQueryInformationProcess = GetFunctionAddress(0xA405E60);

    uintptr_t pNtVirtualAllocEx = GetFunctionAddress(0xC86105CA);
    uintptr_t pNtVirtualFreeEx = GetFunctionAddress(0xB5567B67);
    uintptr_t NtProtectVirtualEx = GetFunctionAddress(0xA4D0D586);

    uintptr_t NtDuplicate = GetFunctionAddress(0x781AA9F7);

    // Cast function pointers for calling
    f_NtOpenProcess _NtOpenProcess;
    f_NtReadVirtualMemory _NtReadVirtualMemory;
    f_NtWriteVirtualMemory _NtWriteVirtualMemory;
    f_NtQuerySystemInformation _NtQuerySystemInformation;

    _NtOpenProcess = (f_NtOpenProcess)ntOpen;
    _NtReadVirtualMemory = (f_NtReadVirtualMemory)pNtRead;
    _NtWriteVirtualMemory = (f_NtWriteVirtualMemory)pNtWrite;
    _NtQuerySystemInformation = (f_NtQuerySystemInformation)pNtSysInfo;

    // Enumerate processes to find target CS2 (Counter-Strike 2)
    ULONG bufferSize = 0;
    _NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    void* buffer = malloc(size_t(bufferSize));
    _NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);

    PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)buffer;
    DWORD targetPid = 0;

    while (true) {
        if (pCurrent->ImageName.Buffer != NULL) {
            if (_wcsicmp(pCurrent->ImageName.Buffer, L"cs2.exe") == 0) {
                targetPid = (DWORD)pCurrent->UniqueProcessId;
                break;
            }
        }
        if (pCurrent->NextEntryOffset == 0)
            break;
        pCurrent = (PSYSTEM_PROCESS_INFORMATION)((uintptr_t)pCurrent + pCurrent->NextEntryOffset);
    }
    free(buffer);

    // Initialize client ID and object attributes for target process
    CLIENT_ID cid = { 0 };
    cid.UniqueProcess = (HANDLE)(uintptr_t)targetPid;
    cid.UniqueThread = 0;

    OBJECT_ATTRIBUTES oa;
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.Attributes = 0;
    oa.ObjectName = NULL;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    // Extract and store System Service Numbers (SSNs) for indirect syscalls
    g_ntOpen = ntOpen;
    g_ssn = GetSSN(ntOpen, expected);
    g_ssn_read = GetSSN(pNtRead, expected);
    g_ssn_write = GetSSN(pNtWrite, expected);

    g_ssn_QSI = GetSSN(pNtSysInfo, expected);
    g_ssn_thread = GetSSN(pNtCreateThreadEx, expected);
    g_ssn_QIP = GetSSN(pNtQueryInformationProcess, expected);

    g_ssn_allocate = GetSSN(pNtVirtualAllocEx, expected);
    g_ssn_free = GetSSN(pNtVirtualFreeEx, expected);
    g_ssn_protect = GetSSN(NtProtectVirtualEx, expected);
    printf("[*] Real hash for NtDuplicateObject: %X\n", MyHasher("NtDuplicateObject"));

    if (NtDuplicate == 0) {
        printf("[-] Error: Could not find NtDuplicateObject by hash!\n");
        return 1;
    }

    g_ssn_duplicate = GetSSN(NtDuplicate, expected);
    printf("[+] NtDuplicateObject SSN: %d\n", g_ssn_duplicate);


    DWORD dwDesiredAccess = 0x0438;
    HANDLE hProcess = 0;
    NTSTATUS status = Syscall_NtOpenProcess(&hProcess, dwDesiredAccess, &oa, &cid);

    // Query remote process PEB (Process Environment Block) to locate module list
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS qipStatus = Syscall_NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
    uintptr_t remoteLdr = 0;
    NTSTATUS readStatus = Syscall_NtReadVirtualMemory(hProcess, (PVOID)((uintptr_t)pbi.PebBaseAddress + 0x18), &remoteLdr, sizeof(remoteLdr), NULL);
    if (readStatus == 0) {
        printf("[+] Ldr found at: %p\n", (void*)remoteLdr);
    }

    // Walk the LDR (Loader Data Table) to find client.dll
    uintptr_t listHeadAddr = remoteLdr + 0x10;
    uintptr_t currentEntry = 0;
    readStatus = Syscall_NtReadVirtualMemory(hProcess, (PVOID)listHeadAddr, &currentEntry, sizeof(currentEntry), NULL);
    uintptr_t clientBase = 0;

    while (currentEntry != listHeadAddr) {
        LDR_DATA_TABLE_ENTRY entry;
        readStatus = Syscall_NtReadVirtualMemory(hProcess, (PVOID)currentEntry, &entry, sizeof(entry), NULL);
        if (readStatus == 0) {
            wchar_t* dllName = (wchar_t*)malloc(entry.BaseDllName.Length + sizeof(wchar_t));
            if (dllName) {
                readStatus = Syscall_NtReadVirtualMemory(hProcess, entry.BaseDllName.Buffer, dllName, entry.BaseDllName.Length, NULL);
                if (readStatus == 0) {
                    dllName[entry.BaseDllName.Length / sizeof(wchar_t)] = L'\0';
                    if (_wcsicmp(L"client.dll", dllName) == 0) {
                        clientBase = (uintptr_t)entry.DllBase;
                        printf("[+] client.dll found at: %p\n", entry.DllBase);
                        free(dllName);
                        break;
                    }
                }
                free(dllName);
            }
        }
        currentEntry = (uintptr_t)entry.InLoadOrderLinks.Flink;
        if (currentEntry == 0) break;
    }
    
    // Allocate memory for system handle table (with retry logic for buffer size)
    PVOID Alloc_buff = NULL;
    SIZE_T size = 1024 * 1024;
    NTSTATUS AllocStatus = Syscall_NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, &Alloc_buff, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (AllocStatus == 0) {
        printf("[+] Memory allocated at: %p\n", Alloc_buff);
    }
    else {
        printf("Memory allocation failed! Status: %X\n", AllocStatus);
    }

    // Query SystemExtendedHandleInformation with dynamic buffer sizing
    while (true) {
        if (Alloc_buff == nullptr) {
            Syscall_NtAllocateVirtualMemory((HANDLE)-1, &Alloc_buff, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }
        NTSTATUS status = Syscall_NtQuerySystemInformation(SystemExtendedHandleInformation, Alloc_buff, (ULONG)size, NULL);

        if (status == 0) {
            break;
        }

        if (status == 0xC0000004) {
            SIZE_T freeSize = 0;
            Syscall_NtFreeVirtualMemory((HANDLE)-1, &Alloc_buff, &freeSize, MEM_RELEASE);

            Alloc_buff = nullptr;
            size += 1024 * 256;
            continue;
        }
        printf("Unexpected error: %X\n", status);
        return 1;
    }

    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)Alloc_buff;
    printf("[+] Number of handles: %d\n", handleInfo->NumberOfHandles);
    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handleEntry = handleInfo->Handles[i];
        if (handleEntry.UniqueProcessId == targetPid) {

        }
    }
    DWORD myPid = GetMyProcessId();
    printf("[*] My Stealthy PID: %d\n", myPid);

    // Get all process information for donor process search
    PVOID buffer1 = NULL; 
    ULONG bufferSize1 = 0;

    _NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize1);
    bufferSize1 += 0x2000; 
    SIZE_T size1 = (SIZE_T)bufferSize1;

    NTSTATUS status1 = Syscall_NtAllocateVirtualMemory((HANDLE)-1, &buffer1, 0, &size1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    USHORT processTypeIndex = 0;
    HANDLE hSelf = NULL;
    
    // Open our own process to determine the process type index from system handle table
    CLIENT_ID selfCid = { (HANDLE)GetCurrentProcessId(), 0 };
    OBJECT_ATTRIBUTES selfOa = { sizeof(selfOa) };
    selfOa.Length = sizeof(OBJECT_ATTRIBUTES);

    _NtOpenProcess(&hSelf, PROCESS_QUERY_LIMITED_INFORMATION, &selfOa, &selfCid);

    // Query handle table again to find process type index
    PVOID Alloc_buff2 = NULL;
    SIZE_T hTableSize = 1024 * 1024;

    while (true) {
        if (Alloc_buff2 == nullptr) {
            Syscall_NtAllocateVirtualMemory((HANDLE)-1, &Alloc_buff2, 0, &hTableSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }
        NTSTATUS status = Syscall_NtQuerySystemInformation(SystemExtendedHandleInformation, Alloc_buff2, (ULONG)hTableSize, NULL);

        if (status == 0) break;

        if (status == 0xC0000004) { // Buffer Too Small
            SIZE_T freeSize = 0;
            Syscall_NtFreeVirtualMemory((HANDLE)-1, &Alloc_buff2, &freeSize, MEM_RELEASE);
            Alloc_buff2 = nullptr;
            hTableSize += 1024 * 256;
            continue;
        }
        return 1;
    }

    PSYSTEM_HANDLE_INFORMATION_EX handleInfo1 = (PSYSTEM_HANDLE_INFORMATION_EX)Alloc_buff2;

    // Locate our handle in the system table to determine process object type index
    if (hSelf) {
        for (ULONG i = 0; i < handleInfo1->NumberOfHandles; i++) {

            if (handleInfo1->Handles[i].UniqueProcessId == GetCurrentProcessId() &&
                (HANDLE)handleInfo1->Handles[i].HandleValue == hSelf) {
                processTypeIndex = handleInfo1->Handles[i].ObjectTypeIndex;
                printf("[*] PROCESS TYPE INDEX DEFINED: %d\n", processTypeIndex);
                break;
            }
        }
        CloseHandle(hSelf); 
    }

    if (processTypeIndex == 0) {
        printf("[-] CRITICAL ERROR: Index not found! Check Admin permissions..\n");
        return 1;
    }
    
    DWORD donorPid = 0;
    HANDLE hDonor = NULL;
    HANDLE hStolen = NULL;

    // Attempt to steal target process handle from donor processes
    if (status1 == 0) {
        status1 = _NtQuerySystemInformation(SystemProcessInformation, buffer1, bufferSize1, &bufferSize1);

        PSYSTEM_PROCESS_INFORMATION pCurrent1 = (PSYSTEM_PROCESS_INFORMATION)buffer1;

        // Candidate donor processes with high privilege/accessibility
        const wchar_t* candidates[] = { L"csrss.exe", L"lsass.exe", L"Steam.exe", L"Discord.exe", L"svchost.exe" };
  
        for (const wchar_t* name : candidates) {
            DWORD currentDonorPid = 0;

            PSYSTEM_PROCESS_INFORMATION pScan = (PSYSTEM_PROCESS_INFORMATION)buffer1;
            while (true) {
                if (pScan->ImageName.Buffer && _wcsicmp(pScan->ImageName.Buffer, name) == 0) {

                    currentDonorPid = (DWORD)(uintptr_t)pScan->UniqueProcessId;

                    if (currentDonorPid == myPid) goto next_candidate;

                    CLIENT_ID dCid = { (HANDLE)currentDonorPid, 0 };
                    OBJECT_ATTRIBUTES dOa = { sizeof(dOa) };

                    if (Syscall_NtOpenProcess(&hDonor, PROCESS_DUP_HANDLE, &dOa, &dCid) == 0) {
                        // Search donor's handle table for target process handles
                        for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
                            auto& entry = handleInfo->Handles[i];
                            ACCESS_MASK myAccess = 0x10 | 0x0400 | 0x0008;
                            
                            // Duplicate target process handle from donor
                            if (entry.UniqueProcessId == (ULONG_PTR)currentDonorPid && entry.ObjectTypeIndex == processTypeIndex) {
                                HANDLE hStolen = NULL;
                               
                                if (Syscall_NtDuplicateObject(hDonor, (HANDLE)entry.HandleValue, (HANDLE)-1, &hStolen, 0, 0, myAccess) == 0) {
                                    PROCESS_BASIC_INFORMATION pbi;
                                    // Verify the stolen handle points to our target CS2 process
                                    if (Syscall_NtQueryInformationProcess(hStolen, 0, &pbi, sizeof(pbi), NULL) == 0) {
                                        if (pbi.UniqueProcessId == (ULONG_PTR)targetPid) {
                                            printf("\n[+] DOMINATION! Хендл угнан у %ws! (Handle: %p)\n", name, hStolen);
                                            hProcess = hStolen;
                                            CloseHandle(hDonor);
                                            goto success;
                                        }
                                    }
                                    CloseHandle(hStolen);
                                }
                            }
                        }
                        CloseHandle(hDonor);
                    }
                }
            next_candidate:
                if (pScan->NextEntryOffset == 0) break;
                pScan = (PSYSTEM_PROCESS_INFORMATION)((uintptr_t)pScan + pScan->NextEntryOffset);
            }
        }
    }
    
    // Validate the stolen handle
    success:
    if (hProcess != NULL) {
        printf("\n[CHECK] Checking a borrowed handle...\n");
        printf("[*] The meaning of the handle in your process: %p\n", hProcess);

        PROCESS_BASIC_INFORMATION pbi_check;
        // Verify handle integrity and target process
        if (Syscall_NtQueryInformationProcess(hProcess, 0, &pbi_check, sizeof(pbi_check), NULL) == 0) {
            printf("[*] Handle points to PID: %d\n", (DWORD)pbi_check.UniqueProcessId);

            if ((DWORD)pbi_check.UniqueProcessId == targetPid) {
                printf("[STATUS] FULL GOOD! PID matches CS2.\n");
            }
            else {
                printf("[STATUS] STOP! PID does not match.\n");
            }
        }
        
        // Test memory read access on target process
        unsigned short mz_check = 0;
        if (Syscall_NtReadVirtualMemory(hProcess, (PVOID)clientBase, &mz_check, sizeof(mz_check), NULL) == 0) {
            if (mz_check == 0x5A4D) { // 'MZ'
                printf("[STATUS] Memory Reading: WORKING! (Found the MZ header)\n");
            }
        }
        else {
            printf("[STATUS] Memory read: ERROR. Handle does not have read permission..\n");
        }
    }

    // Clean up allocated memory
    SIZE_T freeSize = 0;
    Syscall_NtFreeVirtualMemory((HANDLE)-1, &buffer1, &freeSize, MEM_RELEASE);
  
    if (Alloc_buff) {
        SIZE_T freeSize = 0;
        Syscall_NtFreeVirtualMemory((HANDLE)-1, &Alloc_buff, &freeSize, MEM_RELEASE);
    }

    // Ready for game data reading/writing via stolen handle
    //Read<uintptr_t>(hProcess, clientBase + offsets);
    //Write<bool>(hProcess, targetAddress(client+offsets), our bool) 

    while (!GetAsyncKeyState(VK_DELETE)) {}
    return 0;
}
