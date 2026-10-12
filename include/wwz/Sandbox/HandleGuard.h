#pragma once

#include <windows.h>

namespace wwz::sandbox {

// RAII cho handle để tránh leak – pattern chuẩn Windows
class HandleGuard {
public:
    HandleGuard() noexcept = default;
    explicit HandleGuard(HANDLE handle) noexcept : handle_(handle) {}

    ~HandleGuard() { Reset(); }

    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;

    HandleGuard(HandleGuard&& other) noexcept : handle_(other.Release()) {}

    HandleGuard& operator=(HandleGuard&& other) noexcept {
        if (this != &other) {
            Reset(other.Release());
        }
        return *this;
    }

    [[nodiscard]] HANDLE Get() const noexcept { return handle_; }

    [[nodiscard]] HANDLE Release() noexcept {
        HANDLE released = handle_;
        handle_ = nullptr;
        return released;
    }

    void Reset(HANDLE handle = nullptr) noexcept {
        if (IsValid()) {
            ::CloseHandle(handle_);
        }
        handle_ = handle;
    }

    [[nodiscard]] bool IsValid() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE handle_{nullptr};
};

}  // namespace wwz::sandbox
