extern pebBase : qword
extern g_ssn:DWORD
extern g_syscallAddr:QWORD

.code

GetMyPeb PROC
	mov rax, gs:[60h]
	mov [pebBase], rax
	ret
GetMyPeb ENDP           

Syscall_NtOpenProcess PROC
	mov r10, rcx
	mov eax, g_ssn     
    jmp qword ptr [g_syscallAddr]
Syscall_NtOpenProcess ENDP

END
