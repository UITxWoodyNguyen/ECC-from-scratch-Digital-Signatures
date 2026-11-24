cmake_minimum_required(VERSION 3.20)
project(lab4_ecc_signatures LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(WIN32)
    set(PLATFORM_NAME "windows")
else()
    set(PLATFORM_NAME "ubuntu")
endif()

if(MSVC)
    set(COMPILER_NAME "msvc")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(COMPILER_NAME "clang")
else()
    set(COMPILER_NAME "gcc")
endif()

message(STATUS "Platform: ${PLATFORM_NAME}, Compiler: ${COMPILER_NAME}")
message(STATUS "Suggested build dir: ${CMAKE_SOURCE_DIR}/build_${PLATFORM_NAME}_${COMPILER_NAME}/")

if(WIN32)
    if(MSVC)
        set(OPENSSL_ROOT_DIR "D:/UIT/NT219/libs/openssl/msvc" CACHE PATH "OpenSSL root dir" FORCE)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set(OPENSSL_ROOT_DIR "D:/UIT/NT219/libs/openssl/clang" CACHE PATH "OpenSSL root dir" FORCE)
    else()
        set(OPENSSL_ROOT_DIR "D:/UIT/NT219/libs/openssl/gcc" CACHE PATH "OpenSSL root dir" FORCE)
    endif()
else()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set(OPENSSL_ROOT_DIR "$ENV{HOME}/Desktop/nt219lib/openssl/clang" CACHE PATH "OpenSSL root dir" FORCE)
    else()
        set(OPENSSL_ROOT_DIR "$ENV{HOME}/Desktop/nt219lib/openssl/gcc" CACHE PATH "OpenSSL root dir" FORCE)
    endif()
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

option(LAB_WERROR "Treat warnings as errors" OFF)
function(lab_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
        if(LAB_WERROR)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

# In-class task targets
set(TASK_TARGETS task_a task_b task_c task_d task_e task_f)

add_executable(task_a task_a_ec_arith.cpp)
add_executable(task_b task_b_ec_keys.cpp)
add_executable(task_c task_c_ecdh.cpp)
add_executable(task_d task_d_rsa_sig.cpp)
add_executable(task_e task_e_ecdsa.cpp)
add_executable(task_f task_f_eddsa.cpp)

foreach(tgt ${TASK_TARGETS})
    target_link_libraries(${tgt} PRIVATE OpenSSL::Crypto OpenSSL::SSL Threads::Threads)
    if(WIN32)
        target_link_libraries(${tgt} PRIVATE ws2_32 crypt32)
    endif()
    lab_set_warnings(${tgt})
endforeach()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Core static library for home project
add_library(lab_core STATIC
    src/common.cpp
    src/ec_math.cpp
    src/ec_keys.cpp
    src/x25519_edu.cpp
    src/ecies.cpp
    src/sigfile.cpp
    src/rsa_sig.cpp
    src/ecdsa.cpp
    src/eddsa.cpp
    src/seal_open.cpp
)

target_include_directories(lab_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(lab_core PUBLIC
    OpenSSL::Crypto
    OpenSSL::SSL
    Threads::Threads
)

if(WIN32)
    target_link_libraries(lab_core PUBLIC ws2_32 crypt32)
endif()

lab_set_warnings(lab_core)

# Shared dynamic library for Python / GUI bindings
add_library(lab_crypto SHARED
    src/c_api.cpp
)
target_compile_definitions(lab_crypto PRIVATE BUILDING_LAB_CRYPTO_DLL)
target_include_directories(lab_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(lab_crypto PRIVATE lab_core)
if(WIN32)
    target_link_libraries(lab_crypto PRIVATE ws2_32 crypt32)
endif()
lab_set_warnings(lab_crypto)

# Main executable named lab03
add_executable(lab03 src/main.cpp)
target_link_libraries(lab03 PRIVATE lab_core)
lab_set_warnings(lab03)
