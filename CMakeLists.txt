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

foreach(target wwz_sandbox wwz_external SandboxTests)
  target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
endforeach()

enable_testing()
add_test(NAME SandboxTests COMMAND SandboxTests)
