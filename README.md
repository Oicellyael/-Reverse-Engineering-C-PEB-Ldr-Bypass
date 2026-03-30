# 🛠️ Windows x64 Stealth Internals & Indirect Syscall Engine
![C++](https://img.shields.io/badge/C++-00599C?style=flat&logo=cplusplus)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat&logo=windows)

### *Advanced Remote Process Exploration via Manual PEB/LDR Traversal*

---

## 🛡️ Overview
This repository contains a sophisticated low-level C++ framework designed for interacting with the Windows kernel-mode interface from user-mode. By bypassing the standard Windows API (Win32) and even direct `ntdll` calls, this engine achieves a high level of stealth and control. It is specifically engineered to demonstrate advanced techniques in **Manual PE Parsing**, **API Hashing**, and **Indirect System Calls**.

## 🚀 Key Features
* **Indirect Syscall Engine**: Executes system calls by jumping to a legitimate `syscall` instruction within `ntdll.dll` memory. This effectively bypasses EDR/AV call-stack monitoring and instrumentation.
* **Dynamic SSN Extraction**: Automatically resolves **System Service Numbers (SSNs)** by parsing the Export Address Table (EAT) of `ntdll.dll` and analyzing the function stubs.
* **Remote PEB & LDR Parsing**: Manually navigates the **Process Environment Block (PEB)** and linked lists (`InLoadOrderModuleList`) of a target process (e.g., `cs2.exe`) to resolve module base addresses without using `EnumProcessModules`.
* **DJB2 API Hashing**: Replaces sensitive string literals with 32-bit hashes, complicating static analysis and signature-based detection.
* **Stealth-First Access**: Implements granular access masks (e.g., `0x0438`) for `NtOpenProcess` to minimize the footprint of the process handle.

## 🏗️ Architecture & Implementation

### 1. The Assembly Layer (MASM)
Utilizes custom x64 Assembly to directly access the `gs` register (`gs:[60h]`) to retrieve the local PEB address, ensuring zero reliance on `GetModuleHandle`.

### 2. Manual EAT Resolver
A custom implementation of a PE header parser that:
1. Locates the `IMAGE_EXPORT_DIRECTORY`.
2. Iterates through the `AddressOfNames` array.
3. Applies a case-insensitive **DJB2 hash** to find the target function.
4. Maps the index to the function's **Relative Virtual Address (RVA)**.

### 3. Syscall Logic
The engine doesn't just call the resolved address. It:
* Extracts the **SSN** from the function stub.
* Finds a valid `syscall; ret` instruction sequence in `ntdll`.
* Uses a custom ASM trampoline to move the SSN into `rax` and jump to the syscall address.

## 📁 Project Structure
* `src/main.cpp`: Core logic, process enumeration, and remote memory parsing.
* `src/asm.asm`: MASM procedures for PEB access and the syscall trampoline.
* `include/asm.h`: C++ linkage for assembly routines.
* `include/nt_structs.h`: Manual definitions of `LDR_DATA_TABLE_ENTRY`, `UNICODE_STRING`, and other internal structures.

## 💻 Technical Demonstration
The following output demonstrates the engine resolving system-level information, identifying the target process, and parsing the remote module list to locate `client.dll`:

<img width="897" height="799" alt="image" src="https://github.com/user-attachments/assets/e0447d0e-31fd-4c9b-b450-245e360a2db6" />

## 📋 Requirements
* **Architecture**: x64 (mandatory for `gs` register and 64-bit offsets).
* **Compiler**: MSVC (Visual Studio) with **MASM** enabled.
* **SDK**: Windows 10/11 SDK.

## ⚠️ Research Disclaimer
This project is developed strictly for **educational and research purposes** within the fields of Windows Internals/External and Cybersecurity. The primary goal is to explore low-level system architecture and undocumented Windows features.

**Хочешь, я помогу тебе составить список из 5-10 каверзных вопросов, которые могут задать по этому коду, и ответов на них?** Чтобы ты на собеседовании чувствовал себя как рыба в воде.
