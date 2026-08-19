cmake_minimum_required(VERSION 3.25)

project(opencode-beacon-konsole-bridge VERSION 1.0.0 LANGUAGES CXX)

include(CTest)

set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BEACON_BRIDGE_POLICY_ONLY "Build only dependency-light bridge policy tests" OFF)

if(BEACON_BRIDGE_POLICY_ONLY)
    find_package(Qt6 6.8 REQUIRED COMPONENTS Core DBus Test)
    add_executable(bridge_policy_test
        tests/bridge_policy_test.cpp
        src/bridge.cpp
        src/owned_object_registry.cpp
    )
    target_include_directories(bridge_policy_test PRIVATE src)
    target_compile_definitions(bridge_policy_test PRIVATE BEACON_BRIDGE_POLICY_ONLY)
    target_link_libraries(bridge_policy_test PRIVATE Qt6::Core Qt6::DBus Qt6::Test)
    add_test(NAME bridge_policy_test COMMAND bridge_policy_test)
    return()
endif()

set(KONSOLE_SOURCE_DIR "" CACHE PATH "Path to the matching Konsole source tree")
set(KONSOLE_BUILD_DIR "" CACHE PATH "Path to the matching configured Konsole build tree")
set(KONSOLE_APP_LIBRARY "" CACHE FILEPATH "Path to the matching libkonsoleapp library")
set(KONSOLE_PRIVATE_LIBRARY "" CACHE FILEPATH "Path to the matching libkonsoleprivate library")

foreach(required KONSOLE_SOURCE_DIR KONSOLE_BUILD_DIR KONSOLE_APP_LIBRARY KONSOLE_PRIVATE_LIBRARY)
    if(NOT ${required})
        message(FATAL_ERROR "${required} is required; see docs/src/project/konsole-bridge.md")
    endif()
    if(NOT EXISTS "${${required}}")
        message(FATAL_ERROR "${required} does not exist: ${${required}}")
    endif()
endforeach()

set(KONSOLE_CONFIG_HEADER "${KONSOLE_BUILD_DIR}/src/config-konsole.h")
set(KONSOLE_CACHE_FILE "${KONSOLE_BUILD_DIR}/CMakeCache.txt")
if(NOT EXISTS "${KONSOLE_CONFIG_HEADER}")
    message(FATAL_ERROR "KONSOLE_BUILD_DIR is not configured: missing ${KONSOLE_CONFIG_HEADER}")
endif()
if(NOT EXISTS "${KONSOLE_CACHE_FILE}")
    message(FATAL_ERROR "KONSOLE_BUILD_DIR is not configured: missing ${KONSOLE_CACHE_FILE}")
endif()
file(STRINGS "${KONSOLE_CONFIG_HEADER}" configured_konsole_version
    REGEX "^#define KONSOLE_VERSION ")
if(NOT configured_konsole_version MATCHES "^#define KONSOLE_VERSION \"([0-9]+\\.[0-9]+\\.[0-9]+)\"$")
    message(FATAL_ERROR "Could not read the configured Konsole version: ${configured_konsole_version}")
endif()
set(KONSOLE_RELEASE_VERSION "${CMAKE_MATCH_1}")
file(STRINGS "${KONSOLE_CACHE_FILE}" configured_konsole_source
    REGEX "^konsole_SOURCE_DIR:STATIC=")
string(REGEX REPLACE "^konsole_SOURCE_DIR:STATIC=" "" configured_konsole_source
    "${configured_konsole_source}")
file(REAL_PATH "${KONSOLE_SOURCE_DIR}" requested_konsole_source)
file(REAL_PATH "${configured_konsole_source}" configured_konsole_source)
if(NOT requested_konsole_source STREQUAL configured_konsole_source)
    message(FATAL_ERROR
        "KONSOLE_SOURCE_DIR does not match the source that produced KONSOLE_BUILD_DIR")
endif()
foreach(library_kind app private)
    string(TOUPPER "${library_kind}" library_kind_upper)
    set(library_path "${KONSOLE_${library_kind_upper}_LIBRARY}")
    file(REAL_PATH "${library_path}" resolved_library_path)
    get_filename_component(resolved_library_name "${resolved_library_path}" NAME)
    set(expected_library_name "libkonsole${library_kind}.so.${KONSOLE_RELEASE_VERSION}")
    if(NOT resolved_library_name STREQUAL expected_library_name)
        message(FATAL_ERROR
            "KONSOLE_${library_kind_upper}_LIBRARY must resolve to ${expected_library_name}, got ${resolved_library_name}")
    endif()
endforeach()

find_package(ECM 6.8 REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})
include(KDEInstallDirs6)
find_package(Qt6 6.8 REQUIRED COMPONENTS Core DBus Widgets Test)
find_package(KF6 6.8 REQUIRED COMPONENTS CoreAddons I18n XmlGui)

configure_file(konsole_beacon_bridge.in.json konsole_beacon_bridge.json @ONLY)

add_library(konsole_build_interface INTERFACE)
target_include_directories(konsole_build_interface INTERFACE
    "${CMAKE_CURRENT_BINARY_DIR}"
    "${KONSOLE_SOURCE_DIR}/src"
    "${KONSOLE_SOURCE_DIR}/src/characters"
    "${KONSOLE_SOURCE_DIR}/src/colorscheme"
    "${KONSOLE_SOURCE_DIR}/src/decoders"
    "${KONSOLE_BUILD_DIR}/src"
    "${KONSOLE_BUILD_DIR}/src/characters"
    "${KONSOLE_BUILD_DIR}/src/colorscheme"
    "${KONSOLE_BUILD_DIR}/src/decoders"
)
target_link_libraries(konsole_build_interface INTERFACE
    Qt6::Core
    Qt6::DBus
    Qt6::Widgets
    KF6::CoreAddons
    KF6::I18n
    KF6::XmlGui
    "${KONSOLE_APP_LIBRARY}"
    "${KONSOLE_PRIVATE_LIBRARY}"
)

add_library(konsole_beacon_bridge MODULE
    src/bridge.cpp
    src/bridge.h
    src/owned_object_registry.cpp
    src/owned_object_registry.h
    src/plugin.cpp
    src/plugin.h
)
target_link_libraries(konsole_beacon_bridge PRIVATE konsole_build_interface)
set_target_properties(konsole_beacon_bridge PROPERTIES
    LIBRARY_OUTPUT_NAME konsole_beacon_bridge
    PREFIX ""
)

if(BUILD_TESTING)
    add_executable(bridge_policy_test
        tests/bridge_policy_test.cpp
        src/bridge.cpp
        src/owned_object_registry.cpp
    )
    target_include_directories(bridge_policy_test PRIVATE src)
    target_compile_definitions(bridge_policy_test PRIVATE BEACON_BRIDGE_POLICY_ONLY)
    target_link_libraries(bridge_policy_test PRIVATE Qt6::Core Qt6::DBus Qt6::Test)
    add_test(NAME bridge_policy_test COMMAND bridge_policy_test)

    add_executable(plugin_load_test tests/plugin_load_test.cpp)
    target_compile_definitions(plugin_load_test PRIVATE
        BRIDGE_PLUGIN_PATH="$<TARGET_FILE:konsole_beacon_bridge>"
        EXPECTED_KONSOLE_VERSION="${KONSOLE_RELEASE_VERSION}"
    )
    target_link_libraries(plugin_load_test PRIVATE Qt6::Test konsole_build_interface)
    add_dependencies(plugin_load_test konsole_beacon_bridge)
    add_test(NAME plugin_load_test COMMAND plugin_load_test)
endif()

install(TARGETS konsole_beacon_bridge
    LIBRARY DESTINATION "${KDE_INSTALL_PLUGINDIR}/konsoleplugins"
)

configure_file(cmake/uninstall.cmake.in uninstall.cmake @ONLY)
add_custom_target(uninstall
    COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake"
)
