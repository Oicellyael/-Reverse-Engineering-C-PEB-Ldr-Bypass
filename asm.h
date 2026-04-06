#pragma once
#include <cstdint>
#include <windows.h>
#include <cctype>

extern "C" {
    extern uintptr_t pebBase;
    void GetMyPeb();
    DWORD GetMyProcessId();
}

namespace NTDLL {
    extern uintptr_t ldr;
    extern uintptr_t ntBase;
}

// ========== TYPEDEFS =========
typedef LONG NTSTATUS;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* f_NtOpenProcess)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
    );

typedef NTSTATUS(NTAPI* f_NtReadVirtualMemory)(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      BufferSize,
    PSIZE_T     NumberOfBytesRead
    );

typedef NTSTATUS(NTAPI* f_NtWriteVirtualMemory)(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      BufferSize,
    PSIZE_T     NumberOfBytesWritten
    );

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5,
    SystemHandleInformation = 16,
	SystemExtendedHandleInformation = 64
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* f_NtQuerySystemInformation)( 
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
    );

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;     
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;    
    LONG BasePriority;
    HANDLE UniqueProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT   UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* f_NtAllocateVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
    );

typedef NTSTATUS(NTAPI* f_NtFreeVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T   RegionSize,
    ULONG     FreeType
    );

typedef NTSTATUS(NTAPI* f_NtProtectVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T   NumberOfBytesToProtect,
    ULONG     NewAccessProtection,
    PULONG    OldAccessProtection
    );

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;               // 8 байт
    ULONG_PTR UniqueProcessId;  // 8 байт
    ULONG_PTR HandleValue;      // 8 байт
    ULONG GrantedAccess;        // 4 байта
    USHORT CreatorBackTraceIndex; // 2 байта
    USHORT ObjectTypeIndex;     // 2 байта
    ULONG HandleAttributes;     // 4 байта
    ULONG Reserved;             // 4 байта
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX; 

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;  // 8 байт
    ULONG_PTR Reserved;         // 8 байт
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

// ========== SYSCALL DECLARATIONS =========
extern "C" NTSTATUS Syscall_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

extern "C" NTSTATUS Syscall_NtReadVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  BufferSize,
    PSIZE_T NumberOfBytesRead
);

extern "C" NTSTATUS Syscall_NtWriteVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      BufferSize,
    PSIZE_T     NumberOfBytesWritten
);

extern "C" NTSTATUS Syscall_NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

extern "C" NTSTATUS Syscall_NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

extern "C" NTSTATUS Syscall_NtQueryInformationProcess(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass, 
    PVOID ProcessInformation,      
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

extern "C" NTSTATUS Syscall_NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

extern "C" NTSTATUS Syscall_NtFreeVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    PSIZE_T   RegionSize,
    ULONG     FreeType
);

extern "C" NTSTATUS Syscall_NtProtectVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    PSIZE_T   NumberOfBytesToProtect,
    ULONG     NewAccessProtection,
    PULONG    OldAccessProtection
);

extern "C" NTSTATUS Syscall_NtDuplicateObject(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
);

// ========== HELPER FUNCTIONS =========
extern "C" {
    extern DWORD g_ssn;
    extern DWORD g_ssn_read;
    extern DWORD g_ssn_write;
    extern uintptr_t g_syscallAddr;
    extern DWORD g_ssn_thread;
    extern DWORD g_ssn_QSI;
    extern DWORD g_ssn_QIP;
    extern uintptr_t g_ntOpen;
	extern DWORD g_ssn_allocate;
    extern DWORD g_ssn_free;
	extern DWORD g_ssn_protect;
    extern DWORD g_ssn_duplicate;
}

DWORD MyHasher(const char* word);
uintptr_t GetFunctionAddress(DWORD targetHash);
DWORD GetSSN(uintptr_t address, const BYTE* pattern);

template <typename T>
T Read(HANDLE hProc, uintptr_t address) {
    T buffer;
    Syscall_NtReadVirtualMemory(hProc, (PVOID)address, &buffer, sizeof(T), NULL);
    return buffer;
}

template <typename T>
bool Write(HANDLE hProc, uintptr_t address, T value) {
    NTSTATUS status = Syscall_NtWriteVirtualMemory(hProc, (PVOID)address, &value, sizeof(T), NULL);
    return (status == 0);
}
