#include "wwz/Sandbox/CrossProcessIO.h"

#include <windows.h>

#include "wwz/Sandbox/SyscallResolver.h"
#include "wwz/Sandbox/SyscallStub.h"

namespace wwz::sandbox {
namespace {

constexpr std::int32_t kStatusSuccess = 0;
constexpr std::int32_t kStatusAccessDenied = static_cast<std::int32_t>(0xC0000022u);
constexpr std::int32_t kStatusPartialCopy = static_cast<std::int32_t>(0x8000000Du);
constexpr std::int32_t kStatusInvalidParameter = static_cast<std::int32_t>(0xC000000Du);

struct NativeObjectAttributes {
    std::uint32_t length;
    HANDLE rootDirectory;
    void* objectName;
    std::uint32_t attributes;
    void* securityDescriptor;
    void* securityQualityOfService;
};

struct NativeClientId {
    HANDLE uniqueProcess;
    HANDLE uniqueThread;
};

bool IsSuccess(std::int32_t status) noexcept {
    return status >= 0;
}

}  // namespace

bool CrossProcessIO::Open(std::uint32_t pid, std::uint32_t accessMask) noexcept {
    if (pid == 0 || accessMask == 0) {
        lastStatus_ = kStatusInvalidParameter;
        lastBytesTransferred_ = 0;
        return false;
    }
    auto& resolver = SyscallResolver::Instance();
    const SyscallInfo* info = resolver.Get(SyscallId::NtOpenProcess);
    if (info == nullptr || !info->resolved) {
        lastStatus_ = kStatusInvalidParameter;
        lastBytesTransferred_ = 0;
        return false;
    }

    NativeObjectAttributes attributes{};
    attributes.length = sizeof(attributes);
    NativeClientId clientId{reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(pid)), nullptr};
    HANDLE opened = nullptr;
    const std::int32_t status = NtOpenProcess(&opened,
                                              static_cast<ACCESS_MASK>(accessMask),
                                              &attributes,
                                              &clientId,
                                              info->number);
    lastStatus_ = status;
    lastBytesTransferred_ = 0;
    if (!IsSuccess(status) || opened == nullptr) {
        return false;
    }
    process_.Reset(opened);
    return true;
}

bool CrossProcessIO::Read(std::uintptr_t address, void* buffer, std::size_t size) noexcept {
    lastBytesTransferred_ = 0;
    if (!process_.IsValid() || address == 0 || buffer == nullptr || size == 0) {
        lastStatus_ = kStatusInvalidParameter;
        return false;
    }
    const SyscallInfo* info = SyscallResolver::Instance().Get(SyscallId::NtReadVirtualMemory);
    if (info == nullptr || !info->resolved) {
        lastStatus_ = kStatusInvalidParameter;
        return false;
    }

    // So sánh behavior giữa ReadProcessMemory (Win32 API) và NtReadVirtualMemory (native API) để hiểu layer.
    std::size_t transferred = 0;
    lastStatus_ = NtReadVirtualMemory(process_.Get(),
                                      reinterpret_cast<void*>(address),
                                      buffer,
                                      size,
                                      &transferred,
                                      info->number);
    lastBytesTransferred_ = transferred;
    return IsSuccess(lastStatus_) && lastStatus_ != kStatusAccessDenied && lastStatus_ != kStatusPartialCopy;
}

bool CrossProcessIO::Write(std::uintptr_t address, const void* buffer, std::size_t size) noexcept {
    lastBytesTransferred_ = 0;
    if (!process_.IsValid() || address == 0 || buffer == nullptr || size == 0) {
        lastStatus_ = kStatusInvalidParameter;
        return false;
    }
    const SyscallInfo* info = SyscallResolver::Instance().Get(SyscallId::NtWriteVirtualMemory);
    if (info == nullptr || !info->resolved) {
        lastStatus_ = kStatusInvalidParameter;
        return false;
    }

    std::size_t transferred = 0;
    lastStatus_ = NtWriteVirtualMemory(process_.Get(),
                                       reinterpret_cast<void*>(address),
                                       buffer,
                                       size,
                                       &transferred,
                                       info->number);
    lastBytesTransferred_ = transferred;
    return IsSuccess(lastStatus_) && lastStatus_ != kStatusAccessDenied && lastStatus_ != kStatusPartialCopy;
}

void CrossProcessIO::Close() noexcept {
    process_.Reset();
    lastBytesTransferred_ = 0;
}

}  // namespace wwz::sandbox
