OPTION CASEMAP:NONE

.code

PUBLIC NtReadVirtualMemory
NtReadVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [rsp+30h]
    syscall
    ret
NtReadVirtualMemory ENDP

PUBLIC NtWriteVirtualMemory
NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [rsp+30h]
    syscall
    ret
NtWriteVirtualMemory ENDP

PUBLIC NtOpenProcess
NtOpenProcess PROC
    mov r10, rcx
    mov eax, dword ptr [rsp+28h]
    syscall
    ret
NtOpenProcess ENDP

PUBLIC NtProtectVirtualMemory
NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [rsp+30h]
    syscall
    ret
NtProtectVirtualMemory ENDP

END
