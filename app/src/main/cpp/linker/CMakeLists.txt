cmake_minimum_required(VERSION 3.6)

set(UTILS_SOURCE
        bionic_linker.h
        build.cpp
        elfSharedLibData.cpp
        hooks.cpp
        linker.cpp
        linux_syscall_support.h
        locks.h
        log_assert.h
        phaser.c
        plthooks.cpp
        sharedlibs.cpp
        sig_safe_write.c
        sigmux.c
        trampoline.cpp
        abort_with_reason.c
        )

if (${ANDROID_ABI} STREQUAL "x86")
    set(TRAMPOLINE trampoline_x86.c)
elseif (${ANDROID_ABI} STREQUAL "x86_64")
    set(TRAMPOLINE trampoline_x86_64.c)
elseif (${ANDROID_ABI} STREQUAL "arm64-v8a")
    set(TRAMPOLINE trampoline_arm64.c)
elseif (${ANDROID_ABI} STREQUAL "armeabi-v7a")
    set(TRAMPOLINE trampoline_arm.c)
endif ()

message(${TRAMPOLINE})
add_library(linker
        STATIC
        ${UTILS_SOURCE}
        ${TRAMPOLINE}
        )
target_link_libraries(linker)