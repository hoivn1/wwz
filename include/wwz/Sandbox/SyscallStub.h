#pragma once

#include <cstddef>
#include <cstdint>

#include <windows.h>
#include <winternl.h>

extern "C" {

NTSTATUS SyscallNtReadVirtualMemory(HANDLE processHandle,
                                    void* baseAddress,
                                    void* buffer,
                                    std::size_t bufferSize,
                                    std::size_t* numberOfBytesRead,
                                    std::uint32_t syscallNumber);

NTSTATUS SyscallNtWriteVirtualMemory(HANDLE processHandle,
                                     void* baseAddress,
                                     const void* buffer,
                                     std::size_t bufferSize,
                                     std::size_t* numberOfBytesWritten,
                                     std::uint32_t syscallNumber);

NTSTATUS SyscallNtOpenProcess(HANDLE* processHandle,
                              ACCESS_MASK desiredAccess,
                              void* objectAttributes,
                              void* clientId,
                              std::uint32_t syscallNumber);

NTSTATUS SyscallNtProtectVirtualMemory(HANDLE processHandle,
                                       void** baseAddress,
                                       std::size_t* regionSize,
                                       std::uint32_t newProtection,
                                       std::uint32_t* oldProtection,
                                       std::uint32_t syscallNumber);

}
