include_directories(BEFORE ${VM_DIR})
include_directories(BEFORE ${VM_DIR}/${ARCH_SOURCES_DIR})
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(BEFORE ${CLR_DIR}/src/unwinder)
include_directories(${CLR_DIR}/src/debug/ee)
include_directories(${CLR_DIR}/src/gc)
include_directories(${CLR_DIR}/src/gcdump)
include_directories(${CLR_DIR}/src/debug/daccess)

if(CLR_CMAKE_PLATFORM_ARCH_AMD64)
    include_directories(amd64)
    
    set(UNWINDER_SOURCES
        unwinder.cpp
        amd64/unwinder_amd64.cpp
    )
elseif(CLR_CMAKE_PLATFORM_ARCH_ARM)
    include_directories(arm)
    
    set(UNWINDER_SOURCES
        unwinder.cpp
        arm/unwinder_arm.cpp
    )
endif()

convert_to_absolute_path(UNWINDER_SOURCES ${UNWINDER_SOURCES})

if(CLR_CMAKE_PLATFORM_UNIX)
    add_compile_options(-fPIC)
endif(CLR_CMAKE_PLATFORM_UNIX)

if(CLR_CMAKE_PLATFORM_UNIX)    
    add_subdirectory(wks)
endif(CLR_CMAKE_PLATFORM_UNIX)

add_subdirectory(dac)