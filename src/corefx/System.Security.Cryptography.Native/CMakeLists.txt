
project(System.Security.Cryptography.Native)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_definitions(-DPIC=1)

if(CLR_CMAKE_PLATFORM_ARCH_AMD64)
    add_definitions(-DBIT64=1)
elseif(CLR_CMAKE_PLATFORM_ARCH_ARM)
    add_definitions(-DBIT32=1)
else()
    message(FATAL_ERROR "Only ARM and AMD64 is supported")
endif()

find_library(CRYPTO NAMES crypto)
if(CRYPTO STREQUAL CRYPTO-NOTFOUND)
    message(WARNING "Cannot find libcrypto, skipping build for System.Security.Cryptography.Native. .NET cryptography is not expected to function. Try installing libssl-dev (or the appropriate package for your platform)")
    return()
endif()

add_compile_options(-fPIC)

set(NATIVECRYPTO_SOURCES
    openssl.c
)

add_library(System.Security.Cryptography.Native
    SHARED
    ${NATIVECRYPTO_SOURCES}
)

# Disable the "lib" prefix.
set_target_properties(System.Security.Cryptography.Native PROPERTIES PREFIX "")

target_link_libraries(System.Security.Cryptography.Native
  ${CRYPTO}
)

install (TARGETS System.Security.Cryptography.Native DESTINATION .)
