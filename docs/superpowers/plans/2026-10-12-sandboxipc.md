# SandboxIPC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone `D:\RenderUtility\wwz_external` MSVC x64 project containing the defensive `wwz_sandbox` process-I/O library, MASM syscall stubs, tests, and detection notes.

**Architecture:** A static library contains a move-only handle wrapper, a cached ntdll export/syscall-number resolver, four x64 MASM syscall entry points, and a process-I/O facade. A small console target reports the resolved numbers, while a dependency-free test executable exercises only the current process.

**Tech Stack:** C++17, MSVC 19.50+, CMake 3.20+, Windows SDK, MASM x64, Windows Native API types from `Windows.h`/`winternl.h`.

**Spec:** `D:\RenderUtility\wwz_external\docs\superpowers\specs\2026-10-12-sandboxipc-design.md`

## Global Constraints

- Build with MSVC 19.50+ on x64 and C++17.
- Do not use a driver, kdmapper, an unsigned driver, privilege escalation, ntdll patching, or hooks.
- Resolve syscall numbers from the current process's ntdll exports; do not hard-code numbers.
- Use only the caller-supplied process access mask and test only against the current process.
- Keep all process-specific application TODOs empty.

## Review Focus

- A failed or non-standard ntdll stub must fail resolution instead of falling back to a guessed number; tested in the resolver task.
- `HANDLE` ownership must survive moves and close exactly once; tested in the handle task.
- Native calls must preserve the trailing syscall-number ABI argument and return kernel status/partial byte counts; tested in the stub and I/O tasks.
- Access denial and partial copy must remain observable rather than being converted to a generic success; tested in the I/O task.
- MASM must only be enabled for the supported MSVC x64 build and be linked into every consumer; tested by the configure/build task.

### Task 1: Create the standalone CMake project and red tests

**Files:**
- Create: `D:\RenderUtility\wwz_external\CMakeLists.txt`
- Create: `D:\RenderUtility\wwz_external\tests\SandboxTests.cpp`
- Create: `D:\RenderUtility\wwz_external\src\main.cpp`

**Interfaces:**
- Consumes: the public headers listed in later tasks.
- Produces: configured targets `wwz_sandbox`, `wwz_external`, `SandboxTests`, and a CTest entry.

- [ ] **Step 1: Write the failing test**

Create a small assertion-based test executable that includes `wwz/Sandbox/HandleGuard.h`, `SyscallResolver.h`, and `CrossProcessIO.h`, and contains these test names and assertions:

```cpp
void TestHandleGuardRaII();
void TestResolverFindsRead();
void TestCrossProcessIoUsesCurrentProcess();
```

The test should fail to compile because the headers and implementations do not exist yet. The current-process test must use `GetCurrentProcessId()` and read a local `std::uint32_t`, never another PID.

- [ ] **Step 2: Run test to verify it fails**

Run `cmake -S D:\RenderUtility\wwz_external -B D:\RenderUtility\wwz_external\build -A x64` and then `cmake --build D:\RenderUtility\wwz_external\build --config Release --target SandboxTests`.

Expected: configuration succeeds and the build fails because the requested public headers and `wwz_sandbox` sources are not present.

- [ ] **Step 3: Write minimal project targets**

Configure CMake with an empty static library target so the red build reaches the missing-header errors without requiring production sources to exist yet, plus a minimal `src/main.cpp` containing `int main() { return 0; }`:

```cmake
cmake_minimum_required(VERSION 3.20)
project(wwz_external LANGUAGES CXX ASM_MASM)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "wwz_external requires MSVC x64")
endif()
add_library(wwz_sandbox STATIC)
target_include_directories(wwz_sandbox PUBLIC include)
add_executable(wwz_external src/main.cpp)
target_link_libraries(wwz_external PRIVATE wwz_sandbox)
add_executable(SandboxTests tests/SandboxTests.cpp)
target_link_libraries(SandboxTests PRIVATE wwz_sandbox)
enable_testing()
add_test(NAME SandboxTests COMMAND SandboxTests)
```

Add `/W4 /permissive- /utf-8` for MSVC targets and `kernel32`/`user32` only if the linker requires them; do not add a driver library.

- [ ] **Step 4: Run the configured red build**

Run `cmake --build D:\RenderUtility\wwz_external\build --config Release --target SandboxTests`.

Expected: the target graph configures, then `SandboxTests` fails because the requested public headers are not present; the empty library is completed in later tasks.

- [ ] **Step 5: Commit**

No repository commit is possible unless the user initializes a Git repository; retain the files and record the absence of a repository in the final report.

### Task 2: Implement `HandleGuard` and its red-green test

**Files:**
- Create: `D:\RenderUtility\wwz_external\include\wwz\Sandbox\HandleGuard.h`
- Modify: `D:\RenderUtility\wwz_external\tests\SandboxTests.cpp`

**Interfaces:**
- Consumes: `HANDLE` and `CloseHandle` from `Windows.h`.
- Produces: `wwz::sandbox::HandleGuard` with move constructor/assignment, `Get()`, `Release()`, `Reset()`, and `IsValid()`.

- [ ] **Step 1: Write the failing test**

Add a test that creates an event, move-constructs a second guard, asserts the source becomes invalid, lets a guard destruct without `Release()`, and verifies `WaitForSingleObject` on the raw handle returns `WAIT_FAILED` with `ERROR_INVALID_HANDLE`.

- [ ] **Step 2: Run test to verify it fails**

Run `cmake --build D:\RenderUtility\wwz_external\build --config Release --target SandboxTests`.

Expected: compile failure because `HandleGuard` is not defined.

- [ ] **Step 3: Write minimal implementation**

Implement the wrapper as a move-only class with `HANDLE handle_{nullptr};`, a destructor calling `Reset()`, `Reset()` closing only when `IsValid()`, and the required comment: `RAII cho handle để tránh leak – pattern chuẩn Windows`. Use an ASCII equivalent in source if the file encoding cannot preserve the en dash, while retaining the exact Vietnamese wording in the project documentation.

- [ ] **Step 4: Run test to verify it passes**

Run `cmake --build D:\RenderUtility\wwz_external\build --config Release --target SandboxTests` and then `D:\RenderUtility\wwz_external\build\Release\SandboxTests.exe`.

Expected: the handle test passes; resolver/I/O tests may still fail until later tasks.

- [ ] **Step 5: Commit**

Retain the working-tree change because this workspace is not a Git checkout.

### Task 3: Implement resolver cache and red-green resolver test

**Files:**
- Create: `D:\RenderUtility\wwz_external\include\wwz\Sandbox\SyscallResolver.h`
- Create: `D:\RenderUtility\wwz_external\src\Sandbox\SyscallResolver.cpp`
- Modify: `D:\RenderUtility\wwz_external\tests\SandboxTests.cpp`

**Interfaces:**
- Consumes: `GetModuleHandleW`, `GetProcAddress`, and `std::call_once`.
- Produces: `wwz::sandbox::SyscallId`, `SyscallInfo`, and `SyscallResolver::Instance()`, `Initialize()`, `Get()`, and `IsInitialized()`.

- [ ] **Step 1: Write the failing test**

Assert that `SyscallResolver::Instance().Initialize()` is true, `Get(SyscallId::NtReadVirtualMemory)` is non-null, its address is non-null, its `resolved` flag is true, and its number is not the unresolved sentinel. Print all four names/numbers for the final report.

- [ ] **Step 2: Run test to verify it fails**

Run `cmake --build D:\RenderUtility\wwz_external\build --config Release --target SandboxTests`.

Expected: compile failure because `SyscallResolver.h` is missing.

- [ ] **Step 3: Write minimal implementation**

Use one `std::once_flag` and one static `std::array<SyscallInfo, 4>` in the `.cpp`. For each export, call `GetProcAddress(GetModuleHandleW(L"ntdll.dll"), name)`, verify the x64 bytes `4C 8B D1 B8`, copy the immediate at offset four, and mark the entry valid. Preserve the required explanatory comment: `Đây là kỹ thuật học syscall table của Windows, dùng cho mục đích hiểu ABI, không dùng để né phát hiện.` Do not scan or modify any other code if the pattern is absent.

- [ ] **Step 4: Run test to verify it passes**

Run `cmake --build D:\RenderUtility\wwz_external\build --config Release --target SandboxTests` and `SandboxTests.exe`.

Expected: the resolver test passes on a normal Windows x64 ntdll and prints four non-sentinel numbers.

- [ ] **Step 5: Commit**

Retain the working-tree change because no Git repository exists.

### Task 4: Add MASM syscall stubs and current-process I/O tests

**Files:**
- Create: `D:\RenderUtility\wwz_external\include\wwz\Sandbox\SyscallStub.h`
- Create: `D:\RenderUtility\wwz_external\src\Sandbox\SyscallStub.asm`
- Create: `D:\RenderUtility\wwz_external\include\wwz\Sandbox\CrossProcessIO.h`
- Create: `D:\RenderUtility\wwz_external\src\Sandbox\CrossProcessIO.cpp`
- Modify: `D:\RenderUtility\wwz_external\tests\SandboxTests.cpp`

**Interfaces:**
- Consumes: `SyscallResolver::Get()` and `HandleGuard`.
- Produces: four `extern "C"` syscall prototypes and `CrossProcessIO::Open/Read/Write/Close`, `LastStatus()`, `LastBytesTransferred()`.

- [ ] **Step 1: Write the failing test**

Complete `TestCrossProcessIoUsesCurrentProcess()` with:

```cpp
CrossProcessIO io;
CHECK(io.Open(GetCurrentProcessId(), PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION));
const std::uint32_t source = 0x13579BDFu;
std::uint32_t copy = 0;
CHECK(io.Read(reinterpret_cast<std::uintptr_t>(&source), &copy, sizeof(copy)));
CHECK(copy == source);
io.Close();
```

- [ ] **Step 2: Run test to verify it fails**

Run `cmake --build D:\RenderUtility\wwz_external\build --config Release --target SandboxTests`.

Expected: compile failure because the syscall stubs and `CrossProcessIO` are not defined.

- [ ] **Step 3: Write minimal implementation**

Declare the native parameter order followed by a trailing `std::uint32_t syscallNumber`. Implement MASM entry points with `mov r10, rcx`, load the trailing argument from `[rsp+28h]` for the four-parameter `NtOpenProcess` and `[rsp+30h]` for the five-parameter calls, execute `syscall`, and `ret`. In `CrossProcessIO`, build `OBJECT_ATTRIBUTES` and `CLIENT_ID`, call only the resolved stubs, preserve `NTSTATUS`, return false for `STATUS_ACCESS_DENIED` and `STATUS_PARTIAL_COPY`, and never request an access mask other than the caller's argument. Include the comparison comment: `So sánh behavior giữa ReadProcessMemory (Win32 API) và NtReadVirtualMemory (native API) để hiểu layer.` Add the three implementation files to `wwz_sandbox` with `target_sources(wwz_sandbox PRIVATE ...)` in `CMakeLists.txt`.

- [ ] **Step 4: Run test to verify it passes**

Run `cmake --build D:\RenderUtility\wwz_external\build --config Release --target SandboxTests` and `SandboxTests.exe`.

Expected: all handle, resolver, and current-process read tests pass; a direct write test is intentionally absent because the requested test scope is read-only/current-process validation.

- [ ] **Step 5: Commit**

Retain the working-tree change because no Git repository exists.

### Task 5: Add detection notes, report executable, and full verification

**Files:**
- Create: `D:\RenderUtility\wwz_external\include\wwz\Sandbox\DetectionSurface.md`
- Modify: `D:\RenderUtility\wwz_external\src\main.cpp`
- Modify: `D:\RenderUtility\wwz_external\tests\SandboxTests.cpp`

**Interfaces:**
- Consumes: the resolver cache and `wwz_sandbox` public API.
- Produces: a 1–2 page Vietnamese detection note and a console report of all four resolved syscall numbers.

- [ ] **Step 1: Write the failing documentation/report check**

Add a test or verification script assertion that the report executable output contains all four export names and that `DetectionSurface.md` contains the headings `handle`, `access mask`, `call stack`, `ETW`, `ObRegisterCallbacks`, `ETW-TI`, `handle stripping`, and `process protection light`.

- [ ] **Step 2: Run test to verify it fails**

Run `cmake --build D:\RenderUtility\wwz_external\build --config Release --target wwz_external` and inspect the output/document path.

Expected: the report target may build, but the content check fails because the document and report output are not complete.

- [ ] **Step 3: Write minimal implementation**

Write a concise Vietnamese document covering cross-process handle type/access masks, call stacks, ETW and kernel callbacks, Win32 versus native API visibility, and the listed defensive mechanisms. State explicitly that native syscalls still create observable handles and kernel operations, and omit avoidance instructions. Make `main.cpp` initialize the resolver and print each export name, address, and discovered number.

- [ ] **Step 4: Run full verification**

Run:

```powershell
cmake -S D:\RenderUtility\wwz_external -B D:\RenderUtility\wwz_external\build -A x64
cmake --build D:\RenderUtility\wwz_external\build --config Release --parallel
ctest --test-dir D:\RenderUtility\wwz_external\build -C Release --output-on-failure
D:\RenderUtility\wwz_external\build\Release\wwz_external.exe
```

Expected: configure/build exit 0, CTest reports `100% tests passed`, and the report lists four resolved syscall numbers. Capture the exact numbers in the final report; they are Windows-version dependent.

- [ ] **Step 5: Commit**

Retain the working-tree change because no Git repository exists.
