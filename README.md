# \# Windows x64 Subsystem Internals & Indirect System Call Engine
### *Advanced Remote Process Instrumentation via Manual PEB/LDR Traversal*

![C++](https://img.shields.io/badge/C++-00599C?style=flat&logo=cplusplus)
![Assembly](https://img.shields.io/badge/Assembly-MASM_x64-red?style=flat&logo=assemblyscript)
![Security](https://img.shields.io/badge/Research-Security-red?style=flat)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat&logo=windows)

## 🛡️ Project Overview

This repository contains a sophisticated low-level C++ framework designed for high-performance, stealthy interaction with the Windows NT subsystem.By operating independently of the standard Win32 API and direct `ntdll` exports, this engine achieves maximum control and minimal system footprint. It is specifically engineered to demonstrate advanced techniques in **Manual PE Parsing**, **Indirect Control Flow Transitions**, and **Stealthy Handle Hijacking**.

## 🚀 Key Technical Features

* **Stealthy Handle Hijacking**: Acquired access to target processes by **duplicating existing handles** from trusted system entities (e.g., Steam, system services). This approach completely bypasses the need for `OpenProcess`, effectively evading kernel-mode object access callbacks (`ObRegisterCallbacks`).
* **Indirect Syscall Engine**: Implements system call execution by transitioning to legitimate `syscall` instructions within the `ntdll.dll` memory space.This technique evaluates call-stack integrity and minimizes detection by $EDR/AV$ instrumentation.
* **Manual OS Parsing**: Engineered manual **PEB (Process Environment Block)** and **LDR (Loader Data)** parsing routines for stealthy API resolution without standard exports or suspicious WinAPI imports. 
* **Low-Overhead Telemetry**: Implemented high-performance data collection modules by directly accessing internal OS metadata structures, significantly reducing system resource consumption. 

## 🏗️ Architecture & Implementation

### 1. Handle Hijacking Engine
A specialized module designed to acquire process access without generating telemetry associated with handle creation:
1.  Enumerates the system handle table via `NtQuerySystemInformation`. 
2.  Filters handles by object type and target PID.
3.  Identifies "trusted" source processes to minimize suspicion.
4.  Uses `NtDuplicateObject` to clone a valid handle into the local process space.

### 2. Indirect Execution Flow
The engine avoids direct syscall invocation. Instead, it:
* Extracts the **SSN** (System Service Number) from the targeted function prologue.
* Identifies valid `syscall; ret` gadgets within the legitimate system address space.
* Uses a custom **MASM trampoline** to prepare the CPU state and execute an indirect jump to the kernel-mode transition point. 

### 3. Manual Export Resolver
A high-performance PE header parser that resolves system API addresses independently of standard Win32 exports using **DJB2 hashing** for string-less resolution.

## 📁 Project Structure

* `Main.cpp`: Core orchestration, handle hijacking logic, and process memory management.
* `indirect.asm`: MASM procedures for the syscall trampoline and low-level register access.
* `asm.h` / `asm.cpp`: Support routines for the low-level assembly layer. Manual definitions of internal structures (`PEB`, `LDR_DATA_TABLE_ENTRY`, `SYSTEM_HANDLE_TABLE_ENTRY_INFO`). 

## ⚠️ Engineering Research Disclaimer

This project is developed for **educational and research purposes** within the fields of Windows Systems Programming and Cybersecurity.  The primary goal is to explore low-level architectural boundaries and the mechanics of user-to-kernel mode transitions.

