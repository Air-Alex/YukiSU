cmake_minimum_required(VERSION 3.14)
project(yukizygisk_daemon VERSION 1.0.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
    message(FATAL_ERROR "YukiZygisk daemon requires an Android target")
endif()

if(CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
    set(ZYGISKD_TARGET zygiskd64)
elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a")
    set(ZYGISKD_TARGET zygiskd32)
else()
    message(FATAL_ERROR
        "YukiZygisk daemon only supports arm64-v8a and armeabi-v7a")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

get_filename_component(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)

add_executable(${ZYGISKD_TARGET}
    log.cpp
    zygiskd.cpp
    standalone.cpp)
target_include_directories(${ZYGISKD_TARGET} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${REPO_ROOT}
    ${REPO_ROOT}/userspace/ksud/src)
target_compile_options(${ZYGISKD_TARGET} PRIVATE
    -Os -fno-exceptions -fno-rtti
    -ffunction-sections -fdata-sections)
target_link_options(${ZYGISKD_TARGET} PRIVATE
    -Wl,--gc-sections -Wl,--strip-all)
target_link_libraries(${ZYGISKD_TARGET} PRIVATE dl)

set(YUKISU_CLANG_TIDY_CONFIG
    "${CMAKE_CURRENT_SOURCE_DIR}/../.clang-tidy")
include("${REPO_ROOT}/cmake/ClangTidy.cmake")
yukisu_enable_clang_tidy(${ZYGISKD_TARGET} CXX)
