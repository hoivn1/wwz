cmake_minimum_required(VERSION 3.20)
project(wwz_external LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT MSVC)
  message(FATAL_ERROR "wwz_external requires an MSVC generator")
endif()

if(MSVC_VERSION LESS 1950)
  message(FATAL_ERROR "wwz_external requires MSVC 19.50 or newer")
endif()

if(NOT CMAKE_GENERATOR MATCHES "^Visual Studio")
  message(FATAL_ERROR "wwz_external requires a Visual Studio generator")
endif()

if(NOT CMAKE_GENERATOR_PLATFORM STREQUAL "x64")
  message(FATAL_ERROR "wwz_external requires the exact Visual Studio x64 platform")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "wwz_external requires 8-byte pointers")
endif()

enable_language(ASM_MASM)

add_library(wwz_sandbox STATIC)
target_include_directories(wwz_sandbox PUBLIC include)
target_sources(wwz_sandbox PRIVATE
  src/Sandbox/SyscallResolver.cpp
  src/Sandbox/SyscallStub.asm
  src/Sandbox/CrossProcessIO.cpp
)

add_executable(wwz_external src/main.cpp)
target_link_libraries(wwz_external PRIVATE wwz_sandbox)

add_executable(SandboxTests tests/SandboxTests.cpp)
target_link_libraries(SandboxTests PRIVATE wwz_sandbox)

foreach(target wwz_sandbox wwz_external SandboxTests)
  target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
endforeach()

enable_testing()
add_test(NAME SandboxTests COMMAND SandboxTests)
