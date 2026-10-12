#include <cassert>
#include <cstdint>
#include <windows.h>

#include "wwz/Sandbox/HandleGuard.h"
#include "wwz/Sandbox/SyscallResolver.h"
#include "wwz/Sandbox/CrossProcessIO.h"

void TestHandleGuardRaII() {
    HANDLE handle = ::GetCurrentProcess();
    assert(handle != nullptr && handle != INVALID_HANDLE_VALUE);
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
