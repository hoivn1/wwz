# SandboxIPC Design

## Goal

Create a standalone Windows x64/C++17 project at `D:\RenderUtility\wwz_external` that demonstrates process-handle and native-system-call mechanics for defensive systems research. The module must use only the caller's existing permissions and must not include drivers, privilege escalation, hooks, ntdll patching, or process-specific offsets.

## Scope and constraints

- Build with MSVC 19.50+ on x64 and C++17.
- Keep the module in `include/wwz/Sandbox/` and `src/Sandbox/`.
- Build `wwz_sandbox` as a static library and link it into a small `wwz_external` executable and `SandboxTests` test executable.
- Use a MASM x64 source file for syscall entry stubs; no inline assembly or kernel component is needed.
- Resolve `NtReadVirtualMemory`, `NtWriteVirtualMemory`, `NtOpenProcess`, and `NtProtectVirtualMemory` from the current process's `ntdll.dll` and extract the syscall number from the normal x64 stub pattern.
- Treat a non-matching or unavailable stub as a resolution failure. Do not scan another module, patch code, hook exports, or substitute a hard-coded syscall number.
- Expose status and transferred-byte diagnostics so `STATUS_ACCESS_DENIED` and `STATUS_PARTIAL_COPY` are observable to callers.
- Tests operate only on the current process.

## Architecture

`SyscallResolver` owns a process-wide, thread-safe cache populated with `GetModuleHandleW(L"ntdll.dll")` and `GetProcAddress`. Each cache entry stores the export address and the extracted 32-bit syscall number. The extraction accepts the documented x64 prefix `4C 8B D1 B8 <imm32>`; a mismatch fails the entry without attempting a bypass.

`SyscallStub.asm` exports four C-linkage entry points. Their C++ signatures match the corresponding native call followed by one trailing `uint32_t syscallNumber` argument. The MASM body copies that trailing number into `EAX`, moves `RCX` to `R10`, executes `syscall`, and returns the kernel status. The trailing argument is read at its ABI-defined stack offset and is never forwarded as a native parameter.

`CrossProcessIO` resolves the cache on first use, opens a process with the exact access mask supplied by its caller through `NtOpenProcess`, and stores the resulting handle in `HandleGuard`. `Read` and `Write` call the corresponding stubs and return `true` only for `NT_SUCCESS(status)` with the requested operation attempted. The last status and byte count remain available for diagnostics; partial copies return `false` while preserving the transferred count. `Close` is idempotent.

## Public interfaces

### HandleGuard

`HandleGuard` is move-only, closes a valid `HANDLE` in its destructor, and exposes `Get()`, `Release()`, `Reset()`, and `IsValid()`. Both `nullptr` and `INVALID_HANDLE_VALUE` are treated as invalid.

### SyscallResolver

`SyscallId` enumerates the four required exports. `SyscallInfo` reports the export name, resolved address, syscall number, and validity. `SyscallResolver::Instance().Initialize()` performs the one-time cache fill; `Get(SyscallId)` returns a stable pointer to an entry or `nullptr` for an unknown id.

### CrossProcessIO

The required methods are:

```cpp
bool Open(std::uint32_t pid, std::uint32_t accessMask);
bool Read(std::uintptr_t addr, void* buf, std::size_t size);
bool Write(std::uintptr_t addr, const void* buf, std::size_t size);
void Close();
```

Additional read-only diagnostics are `LastStatus()` and `LastBytesTransferred()`.

## Error handling

- Resolver failure leaves each entry invalid and causes `Open`, `Read`, and `Write` to fail without issuing a syscall.
- Invalid local arguments, an invalid handle, or a zero-length operation are rejected with `STATUS_INVALID_PARAMETER`.
- `STATUS_ACCESS_DENIED` is preserved as the last status and returns `false`.
- `STATUS_PARTIAL_COPY` is preserved as the last status, returns `false`, and exposes the partial byte count.
- A failed `NtOpenProcess` never replaces the current handle.
- `Close` resets the handle and diagnostic byte count.

## Detection notes

The module intentionally uses native syscalls as an ABI study. Native calls still create ordinary process handles and kernel-visible memory operations; the documentation must describe those detection surfaces and common defensive controls without offering evasion guidance. See `include/wwz/Sandbox/DetectionSurface.md`.

## Verification

`SandboxTests` covers move-only RAII and automatic close, successful resolution of `NtReadVirtualMemory`, opening the current PID, reading a local value through the native API, and reporting all four resolved syscall numbers. The CMake build must compile MASM, link `wwz_sandbox` into `wwz_external` and `SandboxTests`, and pass `ctest --test-dir build -C Release --output-on-failure`.
