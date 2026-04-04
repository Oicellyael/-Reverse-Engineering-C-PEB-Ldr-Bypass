# \# Windows x64 Subsystem Internals & Indirect System Call Engine
### *Advanced Remote Process Instrumentation via Manual PEB/LDR Traversal*

![C++](https://img.shields.io/badge/C++-00599C?style=flat&logo=cplusplus)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat&logo=windows)


## 🛡️ Project Overview

This repository contains a sophisticated low-level C++ framework designed for high-performance interaction with the Windows NT subsystem. By operating independently of the standard Win32 API and direct `ntdll` exports, this engine achieves maximum control and minimal system footprint. It is specifically engineered to demonstrate advanced techniques in **Manual PE Parsing**, **Dynamic SSN Discovery**, and **Indirect Control Flow Transitions**.

## 🚀 Key Technical Features

  * **Indirect Syscall Engine**: Implements system call execution by transitioning to legitimate `syscall` instructions within the `ntdll.dll` memory space. This technique evaluates call-stack integrity and minimizes detection by instrumentation-based security solutions.
  * **Automated SSN Extraction**: Dynamically resolves **System Service Numbers (SSNs)** at runtime by parsing the Export Address Table (EAT) of `ntdll.dll`, ensuring full compatibility across diverse Windows kernel versions.
  * **Remote Subsystem Enumeration**: Manually navigates the **Process Environment Block (PEB)** and linked lists (`InLoadOrderModuleList`) of a target process to resolve module base addresses, bypassing standard enumeration APIs.
  * **Compile-Time Obfuscation**: Utilizes **DJB2 hashing** for API resolution, replacing sensitive string literals with 32-bit hashes to enhance the binary's resistance to static analysis.
  * **Granular Access Control**: Implements precise access mask configurations for process handle management, optimizing the application's security posture and visibility.

## 🏗️ Architecture & Implementation

### 1\. Low-Level Assembly Layer (MASM)

Leverages custom x64 Assembly to interface directly with the Thread Information Block (`gs:[60h]`). This allows for local PEB retrieval with zero external dependencies, ensuring a self-contained execution environment.

### 2\. Manual Export Resolver

A high-performance PE header parser that:

1.  Locates the `IMAGE_EXPORT_DIRECTORY` via the Data Directory.
2.  Implements a fast-path search through the `AddressOfNames` array.
3.  Uses a case-insensitive **DJB2 hash** algorithm for O(n) function resolution.
4.  Maps indices to **Relative Virtual Addresses (RVA)** for precise memory mapping.

### 3\. Indirect Execution Flow

The engine avoids direct syscall invocation. Instead, it:

  * Extracts the **SSN** from the targeted function prologue.
  * Identifies valid `syscall; ret` gadgets within the legitimate system address space.
  * Uses a custom ASM trampoline to prepare the CPU state and execute an indirect jump to the kernel-mode transition point.

## 📁 Project Structure

  * `src/main.cpp`: Core orchestration, process enumeration, and remote memory logic.
  * `src/asm.asm`: MASM procedures for low-level register access and the syscall trampoline.
  * `include/nt_structs.h`: Manual definitions of internal structures (`LDR_DATA_TABLE_ENTRY`, `PEB`, etc.), reducing reliance on large SDK headers.


<img width="897" height="605" alt="image" src="https://github.com/user-attachments/assets/4f6782b4-dbc1-49f1-b770-020fb31fbc89" />


## ⚠️ Engineering Research Disclaimer

This project is developed for **educational and research purposes** within the fields of Windows Systems Programming and Cybersecurity. The primary goal is to explore low-level architectural boundaries and the mechanics of user-to-kernel mode transitions.
