cmake_minimum_required(VERSION 2.8.12.2)

if(CMAKE_SYSTEM_PROCESSOR STREQUAL x86_64 OR CMAKE_SYSTEM_PROCESSOR STREQUAL amd64 OR CMAKE_SYSTEM_PROCESSOR STREQUAL AMD64)
    set(PAL_CMAKE_PLATFORM_ARCH_AMD64 1)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL armv7l)
    set(PAL_CMAKE_PLATFORM_ARCH_ARM 1)
endif()

# Compile options
add_definitions(-DPLATFORM_UNIX=1)
add_definitions(-D__LINUX__=1)
add_definitions(-DLP64COMPATIBLE=1)
add_definitions(-DFEATURE_PAL=1)
add_definitions(-DCORECLR=1)
add_definitions(-DPIC=1)
if(PAL_CMAKE_PLATFORM_ARCH_AMD64)
  add_definitions(-DBIT64=1)
  add_definitions(-D_WIN64=1)
elseif(PAL_CMAKE_PLATFORM_ARCH_ARM)
  add_definitions(-DBIT32=1)
  add_definitions(-D_WIN32=1)
endif()

add_compile_options(-Wno-empty-body)

add_subdirectory(palsuite)

