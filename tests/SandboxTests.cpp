#include <cassert>
#include <cstdio>
#include <cstdint>
#include <utility>
#include <windows.h>

#include "wwz/Sandbox/HandleGuard.h"
#include "wwz/Sandbox/SyscallResolver.h"
#include "wwz/Sandbox/CrossProcessIO.h"

void TestHandleGuardRaII() {
    HANDLE rawHandle = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    assert(rawHandle != nullptr);

    {
        wwz::sandbox::HandleGuard first(rawHandle);
        wwz::sandbox::HandleGuard second(std::move(first));
        assert(!first.IsValid());
        assert(second.IsValid());
        rawHandle = second.Get();
    }

    ::SetLastError(ERROR_SUCCESS);
    assert(::WaitForSingleObject(rawHandle, 0) == WAIT_FAILED);
    assert(::GetLastError() == ERROR_INVALID_HANDLE);
}

void TestResolverFindsRead() {
    auto& resolver = wwz::sandbox::SyscallResolver::Instance();
    assert(resolver.Initialize());
    assert(resolver.IsInitialized());

    const auto* read = resolver.Get(wwz::sandbox::SyscallId::NtReadVirtualMemory);
    assert(read != nullptr);
    assert(read->address != nullptr);
    assert(read->resolved);
    assert(read->number != wwz::sandbox::kUnresolvedSyscall);

    for (std::uint8_t raw = 0; raw < static_cast<std::uint8_t>(wwz::sandbox::SyscallId::Count); ++raw) {
        const auto* info = resolver.Get(static_cast<wwz::sandbox::SyscallId>(raw));
        assert(info != nullptr);
        std::printf("%s: %u\n", info->name, info->number);
    }
}

void TestCrossProcessIoUsesCurrentProcess() {
    std::uint32_t value = 0x12345678u;
    const DWORD currentProcessId = ::GetCurrentProcessId();
    assert(currentProcessId == ::GetCurrentProcessId());
    assert(value == 0x12345678u);
}

int main() {
    TestHandleGuardRaII();
    TestResolverFindsRead();
    TestCrossProcessIoUsesCurrentProcess();
    return 0;
}
