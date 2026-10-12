# Task 2 Report: HandleGuard

## Files

- Added `include/wwz/Sandbox/HandleGuard.h`.
- Updated `tests/SandboxTests.cpp` with a real move/destruction/invalid-handle test.

## Implementation

`wwz::sandbox::HandleGuard` owns a Windows `HANDLE`, is move-only, closes valid handles in its destructor and `Reset`, and provides `Get`, `Release`, `Reset`, and `IsValid`.

## Commands and output

- `cmake -S . -B build -G 'Visual Studio 17 2022' -A x64`
  - Could not run: `cmake` is not installed or available on `PATH`.
- `git diff --check`
  - Passed; Git only reported its normal LF-to-CRLF warning for `tests/SandboxTests.cpp`.
- The requested red-stage build and green-stage build/executable run could not be executed because CMake is unavailable and no `build` directory exists.

## Commit

`475a6f69797999185095bdac5fa45600aefa8427` (`Implement Sandbox HandleGuard RAII wrapper`).

## Concerns

- Runtime Windows test verification remains pending until a machine with CMake and the MSVC x64 toolchain is available.
