#pragma once

#include <cstddef>
#include <cstdint>

#include <windows.h>

extern "C" {

std::int32_t NtReadVirtualMemory(HANDLE processHandle,
                                 void* baseAddress,
                                 void* buffer,
                                 std::size_t bufferSize,
                                 std::size_t* numberOfBytesRead,
                                 std::uint32_t syscallNumber);

std::int32_t NtWriteVirtualMemory(HANDLE processHandle,
                                  void* baseAddress,
                                  const void* buffer,
                                  std::size_t bufferSize,
                                  std::size_t* numberOfBytesWritten,
                                  std::uint32_t syscallNumber);

std::int32_t NtOpenProcess(HANDLE* processHandle,
                           ACCESS_MASK desiredAccess,
                           void* objectAttributes,
                           void* clientId,
                           std::uint32_t syscallNumber);

std::int32_t NtProtectVirtualMemory(HANDLE processHandle,
                                    void** baseAddress,
                                    std::size_t* regionSize,
                                    std::uint32_t newProtection,
                                    std::uint32_t* oldProtection,
                                    std::uint32_t syscallNumber);

}
