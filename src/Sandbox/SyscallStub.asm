OPTION CASEMAP:NONE

.code

PUBLIC SyscallNtReadVirtualMemory
SyscallNtReadVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [rsp+30h]
    syscall
    ret
SyscallNtReadVirtualMemory ENDP

PUBLIC SyscallNtWriteVirtualMemory
SyscallNtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [rsp+30h]
    syscall
    ret
SyscallNtWriteVirtualMemory ENDP

PUBLIC SyscallNtOpenProcess
SyscallNtOpenProcess PROC
    mov r10, rcx
    mov eax, dword ptr [rsp+28h]
    syscall
    ret
SyscallNtOpenProcess ENDP

PUBLIC SyscallNtProtectVirtualMemory
SyscallNtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [rsp+30h]
    syscall
    ret
SyscallNtProtectVirtualMemory ENDP

END
