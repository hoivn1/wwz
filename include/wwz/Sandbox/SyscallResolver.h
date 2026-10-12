#pragma once

#include <cstdint>

namespace wwz::sandbox {

enum class SyscallId : std::uint8_t {
    NtReadVirtualMemory = 0,
    NtWriteVirtualMemory,
    NtOpenProcess,
    NtProtectVirtualMemory,
    Count,
};

inline constexpr std::uint32_t kUnresolvedSyscall = 0xFFFFFFFFu;

struct SyscallInfo {
    const char* name{nullptr};
    void* address{nullptr};
    std::uint32_t number{kUnresolvedSyscall};
    bool resolved{false};
};

class SyscallResolver final {
public:
    static SyscallResolver& Instance() noexcept;

    bool Initialize() noexcept;
    const SyscallInfo* Get(SyscallId id) const noexcept;
    bool IsInitialized() const noexcept;

private:
    SyscallResolver() = default;
};

}  // namespace wwz::sandbox
