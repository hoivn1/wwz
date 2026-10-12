#pragma once

#include <cstddef>
#include <cstdint>

#include <winternl.h>

#include "wwz/Sandbox/HandleGuard.h"

namespace wwz::sandbox {

class CrossProcessIO final {
public:
    bool Open(std::uint32_t pid, std::uint32_t accessMask) noexcept;
    bool Read(std::uintptr_t address, void* buffer, std::size_t size) noexcept;
    bool Write(std::uintptr_t address, const void* buffer, std::size_t size) noexcept;
    void Close() noexcept;

    [[nodiscard]] NTSTATUS LastStatus() const noexcept { return lastStatus_; }
    [[nodiscard]] std::size_t LastBytesTransferred() const noexcept { return lastBytesTransferred_; }

private:
    HandleGuard process_;
    NTSTATUS lastStatus_{0};
    std::size_t lastBytesTransferred_{0};
};

}  // namespace wwz::sandbox
