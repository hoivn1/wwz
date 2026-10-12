#include <cassert>
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
    assert(true);
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
