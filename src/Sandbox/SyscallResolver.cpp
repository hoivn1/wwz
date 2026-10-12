#include "wwz/Sandbox/SyscallResolver.h"

#include <array>
#include <cstring>
#include <mutex>

#include <windows.h>

namespace wwz::sandbox {
namespace {

constexpr std::array<const char*, 4> kNames{
    "NtReadVirtualMemory",
    "NtWriteVirtualMemory",
    "NtOpenProcess",
    "NtProtectVirtualMemory",
};

std::once_flag g_initializeFlag;
std::array<SyscallInfo, 4> g_entries{};
bool g_initialized = false;

void Populate() noexcept {
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    bool allResolved = ntdll != nullptr;

    for (std::size_t i = 0; i < kNames.size(); ++i) {
        SyscallInfo& entry = g_entries[i];
        entry.name = kNames[i];
        entry.address = nullptr;
        entry.number = kUnresolvedSyscall;
        entry.resolved = false;

        if (ntdll == nullptr) {
            allResolved = false;
            continue;
        }

        FARPROC proc = ::GetProcAddress(ntdll, kNames[i]);
        if (proc == nullptr) {
            allResolved = false;
            continue;
        }

        const auto* stub = reinterpret_cast<const unsigned char*>(proc);
        if (stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1 || stub[3] != 0xB8) {
            allResolved = false;
            continue;
        }

        std::uint32_t number = 0;
        std::memcpy(&number, stub + 4, sizeof(number));
        if (number == kUnresolvedSyscall) {
            allResolved = false;
            continue;
        }
        entry.address = reinterpret_cast<void*>(proc);
        entry.number = number;
        entry.resolved = true;
    }

    if (!allResolved) {
        for (std::size_t i = 0; i < g_entries.size(); ++i) {
            g_entries[i].address = nullptr;
            g_entries[i].number = kUnresolvedSyscall;
            g_entries[i].resolved = false;
        }
    }
    g_initialized = allResolved;
}

}  // namespace

SyscallResolver& SyscallResolver::Instance() noexcept {
    static SyscallResolver resolver;
    return resolver;
}

bool SyscallResolver::Initialize() noexcept {
    // Đây là kỹ thuật học syscall table của Windows, dùng cho mục đích hiểu ABI, không dùng để né phát hiện.
    std::call_once(g_initializeFlag, Populate);
    return g_initialized;
}

const SyscallInfo* SyscallResolver::Get(SyscallId id) const noexcept {
    const_cast<SyscallResolver*>(this)->Initialize();

    const auto index = static_cast<std::size_t>(id);
    if (index >= g_entries.size()) {
        return nullptr;
    }
    return &g_entries[index];
}

bool SyscallResolver::IsInitialized() const noexcept {
    const_cast<SyscallResolver*>(this)->Initialize();
    return g_initialized;
}

}  // namespace wwz::sandbox
