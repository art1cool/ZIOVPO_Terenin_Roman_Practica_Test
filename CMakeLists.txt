cmake_minimum_required(VERSION 3.21)

project(AntivirusClient LANGUAGES C CXX)

if(NOT WIN32)
    message(FATAL_ERROR "This project can only be built on Windows.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_VS_PLATFORM_NAME STREQUAL "Win32")
    set(ANTIVIRUS_PLATFORM "x86")
elseif(DEFINED CMAKE_VS_PLATFORM_NAME AND NOT CMAKE_VS_PLATFORM_NAME STREQUAL "")
    set(ANTIVIRUS_PLATFORM "${CMAKE_VS_PLATFORM_NAME}")
elseif(DEFINED CMAKE_GENERATOR_PLATFORM AND NOT CMAKE_GENERATOR_PLATFORM STREQUAL "")
    if(CMAKE_GENERATOR_PLATFORM STREQUAL "Win32")
        set(ANTIVIRUS_PLATFORM "x86")
    else()
        set(ANTIVIRUS_PLATFORM "${CMAKE_GENERATOR_PLATFORM}")
    endif()
else()
    set(ANTIVIRUS_PLATFORM "x64")
endif()

string(TOLOWER "${ANTIVIRUS_PLATFORM}" ANTIVIRUS_PLATFORM_LOWER)

set(WINDOWS_KITS_BIN_ROOT "C:/Program Files (x86)/Windows Kits/10/bin")
set(WINSDK_BIN_VERSION_DIR "")
if(DEFINED CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION AND
   EXISTS "${WINDOWS_KITS_BIN_ROOT}/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}")
    set(WINSDK_BIN_VERSION_DIR "${WINDOWS_KITS_BIN_ROOT}/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}")
endif()
if(WINSDK_BIN_VERSION_DIR STREQUAL "")
    file(GLOB WINSDK_BIN_CANDIDATES LIST_DIRECTORIES true "${WINDOWS_KITS_BIN_ROOT}/10.*")
    if(WINSDK_BIN_CANDIDATES)
        list(SORT WINSDK_BIN_CANDIDATES COMPARE NATURAL ORDER DESCENDING)
        list(GET WINSDK_BIN_CANDIDATES 0 WINSDK_BIN_VERSION_DIR)
    endif()
endif()
if(NOT EXISTS "${WINSDK_BIN_VERSION_DIR}")
    message(FATAL_ERROR "Windows SDK bin directory was not found.")
endif()

if(ANTIVIRUS_PLATFORM_LOWER STREQUAL "x86")
    set(MIDL_ENV "win32")
    set(MIDL_EXE "${WINSDK_BIN_VERSION_DIR}/x86/midl.exe")
elseif(ANTIVIRUS_PLATFORM_LOWER STREQUAL "arm64")
    set(MIDL_ENV "arm64")
    set(MIDL_EXE "${WINSDK_BIN_VERSION_DIR}/arm64/midl.exe")
else()
    set(MIDL_ENV "x64")
    set(MIDL_EXE "${WINSDK_BIN_VERSION_DIR}/x64/midl.exe")
endif()

if(NOT EXISTS "${MIDL_EXE}")
    message(FATAL_ERROR "midl.exe was not found: ${MIDL_EXE}")
endif()

set(RPC_IDL_FILE "${CMAKE_CURRENT_SOURCE_DIR}/ServiceRpc.idl")
set(RPC_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/rpc")
set(RPC_HEADER "${RPC_GENERATED_DIR}/ServiceRpc.h")
set(RPC_CLIENT_STUB "${RPC_GENERATED_DIR}/ServiceRpcClient.c")
set(RPC_SERVER_STUB "${RPC_GENERATED_DIR}/ServiceRpcServer.c")

add_custom_command(
    OUTPUT
        "${RPC_HEADER}"
        "${RPC_CLIENT_STUB}"
        "${RPC_SERVER_STUB}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${RPC_GENERATED_DIR}"
    COMMAND "${MIDL_EXE}"
        /nologo
        /env ${MIDL_ENV}
        /target NT100
        /I "${CMAKE_CURRENT_SOURCE_DIR}"
        /header "ServiceRpc.h"
        /cstub "ServiceRpcClient.c"
        /sstub "ServiceRpcServer.c"
        /client stub
        /server stub
        /out "${RPC_GENERATED_DIR}"
        "${RPC_IDL_FILE}"
    DEPENDS "${RPC_IDL_FILE}"
    VERBATIM
)

add_custom_target(antivirus_rpc_stubs
    DEPENDS
        "${RPC_HEADER}"
        "${RPC_CLIENT_STUB}"
        "${RPC_SERVER_STUB}"
)

add_executable(AntivirusClient WIN32
    AntivirusClient.cpp
    Tray.cpp
    Tray.h
    ServiceManager.cpp
    RpcMemory.cpp
    "${RPC_CLIENT_STUB}"
)

target_include_directories(AntivirusClient PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${RPC_GENERATED_DIR}"
)

add_dependencies(AntivirusClient antivirus_rpc_stubs)

target_compile_definitions(AntivirusClient PRIVATE
    UNICODE
    _UNICODE
)
if(MSVC)
    target_compile_options(AntivirusClient PRIVATE /utf-8)
endif()

target_link_libraries(AntivirusClient PRIVATE
    user32
    shell32
    gdi32
    advapi32
    winhttp
    rpcrt4
)

add_executable(AntivirusClientService WIN32
    ServiceMain.cpp
    ServiceManager.cpp
    RpcMemory.cpp
    "${RPC_SERVER_STUB}"
)

target_include_directories(AntivirusClientService PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${RPC_GENERATED_DIR}"
)

add_dependencies(AntivirusClientService antivirus_rpc_stubs)

target_compile_definitions(AntivirusClientService PRIVATE
    UNICODE
    _UNICODE
    ANTIVIRUS_SERVICE_HOST
)
if(MSVC)
    target_compile_options(AntivirusClientService PRIVATE /utf-8)
endif()

target_link_libraries(AntivirusClientService PRIVATE
    user32
    advapi32
    userenv
    wtsapi32
    winhttp
    rpcrt4
)

set_target_properties(AntivirusClientService PROPERTIES OUTPUT_NAME "AntivirusClient.Service")

if(MSVC)
    function(copy_runtime_dlls target_name)
        add_custom_command(TARGET ${target_name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy -t $<TARGET_FILE_DIR:${target_name}> $<TARGET_RUNTIME_DLLS:${target_name}>
            COMMAND_EXPAND_LISTS
        )
    endfunction()

    function(copy_msvc_redist_dlls target_name)
        set(_redist_roots)
        file(GLOB _vs_redist_roots_pf LIST_DIRECTORIES true "C:/Program Files/Microsoft Visual Studio/*/*/VC/Redist/MSVC/*")
        file(GLOB _vs_redist_roots_pfx86 LIST_DIRECTORIES true "C:/Program Files (x86)/Microsoft Visual Studio/*/*/VC/Redist/MSVC/*")
        list(APPEND _redist_roots ${_vs_redist_roots_pf} ${_vs_redist_roots_pfx86})
        if(NOT _redist_roots)
            return()
        endif()

        set(_redist_arch "x64")
        if(ANTIVIRUS_PLATFORM_LOWER STREQUAL "x86")
            set(_redist_arch "x86")
        elseif(ANTIVIRUS_PLATFORM_LOWER STREQUAL "arm64")
            set(_redist_arch "arm64")
        endif()

        list(SORT _redist_roots COMPARE NATURAL ORDER DESCENDING)
        set(_msvc_redist_dlls)
        foreach(_redist_root IN LISTS _redist_roots)
            file(GLOB _candidate_dlls "${_redist_root}/${_redist_arch}/Microsoft.VC*.CRT/*.dll")
            if(_candidate_dlls)
                set(_msvc_redist_dlls ${_candidate_dlls})
                break()
            endif()
        endforeach()

        if(NOT _msvc_redist_dlls)
            return()
        endif()

        add_custom_command(TARGET ${target_name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_msvc_redist_dlls} $<TARGET_FILE_DIR:${target_name}>
            COMMAND_EXPAND_LISTS
        )
    endfunction()

    copy_runtime_dlls(AntivirusClient)
    copy_runtime_dlls(AntivirusClientService)
    copy_msvc_redist_dlls(AntivirusClient)
    copy_msvc_redist_dlls(AntivirusClientService)
endif()

install(TARGETS AntivirusClient AntivirusClientService
    RUNTIME DESTINATION "."
)

install(DIRECTORY "$<TARGET_FILE_DIR:AntivirusClient>/"
    DESTINATION "."
    FILES_MATCHING
    PATTERN "*.dll"
)

set(CPACK_GENERATOR "WIX")
set(CPACK_PACKAGE_NAME "AntivirusClient")
set(CPACK_PACKAGE_VENDOR "ZIOVPO")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Antivirus Client and Session Launcher Service")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "AntivirusClient")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_MONOLITHIC_INSTALL ON)
set(CPACK_PACKAGE_FILE_NAME "AntivirusClient-${CPACK_PACKAGE_VERSION}-win-${ANTIVIRUS_PLATFORM_LOWER}")
set(CPACK_WIX_UPGRADE_GUID "D8D2E967-614A-46CD-8A0C-F96D24A0D6F0")
set(CPACK_WIX_ARCHITECTURE "${ANTIVIRUS_PLATFORM_LOWER}")

include(CPack)
