#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <utility>
#include <windows.h>

#include "wwz/Sandbox/HandleGuard.h"
#include "wwz/Sandbox/SyscallResolver.h"
#include "wwz/Sandbox/CrossProcessIO.h"

void Check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "Check failed: %s\n", message);
        std::abort();
    }
}

void TestHandleGuardRaII() {
    HANDLE rawHandle = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    Check(rawHandle != nullptr, "Create event");

    {
        wwz::sandbox::HandleGuard first(rawHandle);
        wwz::sandbox::HandleGuard second(std::move(first));
        Check(!first.IsValid(), "Moved-from guard is invalid");
        Check(second.IsValid(), "Moved-to guard is valid");
        rawHandle = second.Get();
    }

    ::SetLastError(ERROR_SUCCESS);
    Check(::WaitForSingleObject(rawHandle, 0) == WAIT_FAILED, "Destroyed guard closes handle");
    Check(::GetLastError() == ERROR_INVALID_HANDLE, "Closed handle reports invalid handle");
}

void TestResolverFindsRead() {
    auto& resolver = wwz::sandbox::SyscallResolver::Instance();
    Check(resolver.Initialize(), "Resolver initializes");
    Check(resolver.IsInitialized(), "Resolver remains initialized");

    const auto* read = resolver.Get(wwz::sandbox::SyscallId::NtReadVirtualMemory);
    Check(read != nullptr, "Read entry exists");
    Check(read->address != nullptr, "Read entry has address");
    Check(read->resolved, "Read entry is resolved");
    Check(read->number != wwz::sandbox::kUnresolvedSyscall, "Read number is resolved");

    for (std::uint8_t raw = 0; raw < static_cast<std::uint8_t>(wwz::sandbox::SyscallId::Count); ++raw) {
        const auto* info = resolver.Get(static_cast<wwz::sandbox::SyscallId>(raw));
        Check(info != nullptr, "Resolver entry exists");
        Check(info->address != nullptr, "Resolver entry has address");
        Check(info->resolved, "Resolver entry is resolved");
        Check(info->number != wwz::sandbox::kUnresolvedSyscall, "Resolver number is resolved");
        std::printf("%s: %u\n", info->name, info->number);
    }
}

void TestCrossProcessIoUsesCurrentProcess() {
    wwz::sandbox::CrossProcessIO io;
    Check(io.Open(::GetCurrentProcessId(), PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION), "Open current process");
    const std::uint32_t source = 0x13579BDFu;
    std::uint32_t copy = 0;
    Check(io.Read(reinterpret_cast<std::uintptr_t>(&source), &copy, sizeof(copy)), "Read current process");
    Check(copy == source, "Copied value matches source");
    io.Close();
}

int main() {
    TestHandleGuardRaII();
    TestResolverFindsRead();
    TestCrossProcessIoUsesCurrentProcess();
    return 0;
}
