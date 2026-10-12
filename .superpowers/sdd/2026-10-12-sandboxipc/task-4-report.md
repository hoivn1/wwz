# Task 4 Report

Implemented the MASM syscall entry points and current-process native I/O wrapper.

## Changes

- Added `include/wwz/Sandbox/SyscallStub.h` with four C-linkage prototypes whose final argument is the resolved syscall number.
- Added `src/Sandbox/SyscallStub.asm`; `NtOpenProcess` loads `[rsp+28h]` and the three five-parameter stubs load `[rsp+30h]`, then execute `syscall` with `r10 = rcx`.
- Added `CrossProcessIO` using `SyscallResolver::Get()` and `HandleGuard`. It validates handles, pointers, sizes, PID/access masks, preserves NTSTATUS and transferred bytes, and passes through the caller's access mask unchanged.
- Added the required Vietnamese Win32/native API comparison comment.
- Added all three implementation sources to `wwz_sandbox` and completed the current-process read test.

## Verification

The first prescribed build command could not run because `cmake.exe` was not on `PATH`:

```text
The term 'cmake.exe' is not recognized as a name of a cmdlet...
```

Configuration succeeded with the requested x64 Visual Studio generator using the known CMake executable. Release build succeeded:

```text
wwz_sandbox.lib
SandboxTests.exe
```

Release test output resolved:

```text
NtReadVirtualMemory: 63
NtWriteVirtualMemory: 58
NtOpenProcess: 38
NtProtectVirtualMemory: 80
```

`SandboxTests.exe` exited 0. CTest passed 1/1 tests (100%). A Debug build and run also exited 0, exercising the assertion-based current-process open/read path with assertions enabled.

## Concerns

- MASM emits expected warnings for C++-only `/permissive-`, `/utf-8`, and `/W` options inherited from the shared target compile options; they do not affect the build.
- Release assertions are compiled out by the standard `NDEBUG` setting; the Debug run confirms the assertions execute.
